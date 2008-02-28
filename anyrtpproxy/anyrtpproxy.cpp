#include <iostream>

#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "../datatypes.h"

#include "../log.h"
#include "../signalController.h"
#include "../PracticalSocket.h"
#include "../buffer.h"

#include "options.h"
#include <list>

#define MAX_PACKET_SIZE 1500

class OpenSerHost
{
public:
  OpenSerHost() : host_("",0) {};

  IfListElement getHost() {
    Lock lock(mutex);
    return host_;
  }

  u_int16_t getLocalPort() {
    Lock lock(mutex);
    return local_port_;
  }

  void setHost(std::string host, u_int16_t port, u_int16_t local_port)
  {
    Lock lock(mutex);
    if(host_.host_ != host || host_.port_ != port)
      cLog.msg(Log::PRIO_NOTICE) << "openSer Host detected at " << host << ":" << port 
                                 << " received at local port " << local_port;

    host_.host_ = host;
    host_.port_ = port;
    local_port_ = local_port;
  }

private:
  Mutex mutex;
  
  IfListElement host_;
  u_int16_t local_port_;
};

struct ThreadParam
{
  OpenSerHost& open_ser_;
  IfListElement interface_;
};

void* sender(void* p)
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

  try 
  {
    UDPSocket recv_sock(param->interface_.host_, param->interface_.port_);
    UDPSocket send_sock(gOpt.getSendPort());
    IfList remote_host_list(gOpt.getRemoteHosts());

    cLog.msg(Log::PRIO_NOTICE) << "sender listening on: " << param->interface_.toString();

    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    while(1) {
      string remote_host;
      u_int16_t remote_port;
      
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len = recv_sock.recvFrom(buf.getBuf(), buf.getLength(), remote_host, remote_port);
      buf.setLength(len);
      
      param->open_ser_.setHost(remote_host, remote_port, param->interface_.port_);
      
      IfList::const_iterator it = remote_host_list.begin();
      for(;it != remote_host_list.end(); it++)
        send_sock.sendTo(buf.getBuf(), buf.getLength(), it->host_, it->port_);
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "sender(" << param->interface_.toString() << ") exiting because: " << e.what() << std::endl;
  }
  pthread_exit(NULL);
}



void* receiver(void* p)
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p); 
  
  try 
  {
    UDPSocket recv_sock(gOpt.getSendPort());
    UDPSocket send_sock;    
    u_int16_t local_port = 0;

    cLog.msg(Log::PRIO_NOTICE) << "receiver listening for packets from: " << param->interface_.toString();

    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    while(1) {
      string remote_host;
      u_int16_t remote_port;
      
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len = recv_sock.recvFrom(buf.getBuf(), buf.getLength(), remote_host, remote_port);
      buf.setLength(len);

      if(remote_host != param->interface_.host_ || remote_port != param->interface_.port_)
        continue;
      
      IfListElement openSerHost = param->open_ser_.getHost();
      if(openSerHost.host_ == "" || !openSerHost.port_)
      {
        cLog.msg(Log::PRIO_NOTICE) << "no openser host detected till now, ignoring packet";
        continue;
      }

      if(local_port != param->open_ser_.getLocalPort())
      {
        local_port = param->open_ser_.getLocalPort();
        send_sock.setLocalPort(local_port);
      }
      send_sock.sendTo(buf.getBuf(), buf.getLength(), openSerHost.host_, openSerHost.port_);
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "sender(" << param->interface_.toString() << ") exiting because: " << e.what() << std::endl;
  }
  pthread_exit(NULL);
} 

void chrootAndDrop(string const& chrootdir, string const& username)
{
	if (getuid() != 0)
	{
	  std::cerr << "this programm has to be run as root in order to run in a chroot" << std::endl;
		exit(-1);
	}	

  struct passwd *pw = getpwnam(username.c_str());
	if(pw) {
		if(chroot(chrootdir.c_str()))
		{
      std::cerr << "can't chroot to " << chrootdir << std::endl;
      exit(-1);
		}
    std::cout << "we are in chroot jail (" << chrootdir << ") now" << std::endl;
    chdir("/");
		if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid)) 
		{
			std::cerr << "can't drop to user " << username << " " << pw->pw_uid << ":" << pw->pw_gid << std::endl;
			exit(-1);
		}
    std::cout << "dropped user to " << username << " " << pw->pw_uid << ":" << pw->pw_gid << std::endl;
	}
	else 
  {
    std::cerr << "unknown user " << username << std::endl;
    exit(-1);
	}
}

void daemonize()
{
  pid_t pid;

  pid = fork();
  if(pid) exit(0);  
  setsid();
  pid = fork();
  if(pid) exit(0);
  
  std::cout << "running in background now..." << std::endl;

  int fd;
  for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
    close(fd);
  fd=open("/dev/null",O_RDWR);        // stdin
  dup(fd);                            // stdout
  dup(fd);                            // stderr
  umask(027); 
}


int main(int argc, char* argv[])
{
  std::cout << "anyrtpproxy" << std::endl;
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }

  if(gOpt.getChroot())
    chrootAndDrop(gOpt.getChrootDir(), gOpt.getUsername());
  if(gOpt.getDaemonize())
    daemonize();

  cLog.setLogName("anyrtpproxy");
  cLog.msg(Log::PRIO_NOTICE) << "anyrtpproxy started...";
  
  SignalController sig;
  sig.init();

  OpenSerHost open_ser;
  std::list<ThreadParam> params;
  IfList listeners(gOpt.getLocalInterfaces());
  IfList::iterator it = listeners.begin();
  for(;it != listeners.end();++it)
  {
    ThreadParam param = {open_ser, *it};
    params.push_back(param);
    pthread_t senderThread;
    pthread_create(&senderThread, NULL, sender, &(params.back()));
    pthread_detach(senderThread);  
  }

  ThreadParam param = {open_ser, gOpt.getRemoteHosts().front()};
  params.push_back(param);
  pthread_t receiverThread;
  pthread_create(&receiverThread, NULL, receiver, &(params.back()));
  pthread_detach(receiverThread);  
  
	int ret = sig.run();
  
  return ret;
}

