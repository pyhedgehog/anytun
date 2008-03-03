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
#include <map>


#define MAX_PACKET_SIZE 1500

class ControlHost : public Host
{
public:
  ControlHost() : Host("",0) {};
  bool operator<(const ControlHost& cmp_to)
  {
    return port_ < cmp_to.port_;
  }
};

class ControlHostMap
{
public:
  

private:
  Mutex mutex;
    
  std::map<ControlHost, std::pair<UDPSocket*, pthread_t>> control_hosts_;
}

void* sender(void* dont_use_me)
{
  try 
  {
    HostList remote_host_list(gOpt.getRemoteHosts());
    UDPSocket control_sock(gOpt.getControlInterface().addr_, gOpt.getControlInterface().port_);

    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    string remote_host;
    u_int16_t remote_port;
    while(1) {
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len = control_sock_.recvFrom(buf.getBuf(), buf.getLength(), remote_host, remote_port);
      buf.setLength(len);
      
      param->control_.setHost(remote_host, remote_port);

//     SenderThreadParam receiverParam = {control_host, control_sock, sock, gOpt.getRemoteHosts().front()};
//     pthread_t receiverThread;
//     pthread_create(&receiverThread, NULL, receiver, &receiverParam);
//     pthread_detach(receiverThread);  

      
      HostList::const_iterator it = remote_host_list.begin();
      for(;it != remote_host_list.end(); it++)
        param->sock_.sendTo(buf.getBuf(), buf.getLength(), it->addr_, it->port_);
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "sender exiting because: " << e.what() << std::endl;
  }
  pthread_exit(NULL);
}



void* receiver(void* p)
{
//   SenderThreadParam* param = reinterpret_cast<SenderThreadParam*>(p); 
  
//   try 
//   {
//     Buffer buf(u_int32_t(MAX_PACKET_SIZE));
//     string remote_host;
//     u_int16_t remote_port;

//     while(1) {
//       buf.setLength(MAX_PACKET_SIZE);
//       u_int32_t len = param->sock_.recvFrom(buf.getBuf(), buf.getLength(), remote_host, remote_port);
//       buf.setLength(len);

//       if(remote_host != param->first_receiver_.addr_ || remote_port != param->first_receiver_.port_)
//         continue;
      
//       Host control_host = param->control_.getHost();
//       if(control_host.addr_ == "" || !control_host.port_)
//       {
//         cLog.msg(Log::PRIO_NOTICE) << "no control host detected till now, ignoring packet";
//         continue;
//       }

//       param->control_sock_.sendTo(buf.getBuf(), buf.getLength(), control_host.addr_, control_host.port_);
//     }  
//   }
//   catch(std::exception &e)
//   {
//     cLog.msg(Log::PRIO_ERR) << "receiver exiting because: " << e.what() << std::endl;
//   }
//   pthread_exit(NULL);
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

  pthread_t senderThread;
  pthread_create(&senderThread, NULL, sender, NULL);
  pthread_detach(senderThread);
  
  int ret = sig.run();
  return ret;
}

