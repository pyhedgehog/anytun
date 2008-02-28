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

void* worker(void* l)
{
  IfListElement* interface = reinterpret_cast<IfListElement*>(l);

  try 
  {
    UDPSocket recv_sock(interface->host_, interface->port_);
    UDPSocket send_sock;
    IfList remote_host_list = gOpt.getRemoteHosts();

    cLog.msg(Log::PRIO_NOTICE) << "worker listening on: " << interface->toString();

    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    while(1) {
      string remote_host;
      u_int16_t remote_port;
      
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len = recv_sock.recvFrom(buf.getBuf(), buf.getLength(), remote_host, remote_port);
      buf.setLength(len);
      
      IfList::const_iterator it = remote_host_list.begin();
      for(;it != remote_host_list.end(); it++)
        send_sock.sendTo(buf.getBuf(), buf.getLength(), it->host_, it->port_);
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "worker(" << interface->toString() << ") exiting because: " << e.what() << std::endl;
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
  

  IfList listeners(gOpt.getLocalInterfaces());
  IfList::iterator it = listeners.begin();
  for(;it != listeners.end();++it)
  {
    pthread_t workerThread;
    pthread_create(&workerThread, NULL, worker, static_cast<void*>(&(*it)));
    pthread_detach(workerThread);  
  }
	int ret = sig.run();
  
  return ret;
}

