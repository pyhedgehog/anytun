/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>
#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "datatypes.h"

#include "log.h"
#include "signalController.h"
#include "anyCtrOptions.h"

#include "anyCtrSocket.h"
#include "Sockets/ListenSocket.h"
#include "Sockets/SocketHandler.h"


class ThreadParam
{
public:
  ThreadParam() : addr(""), port(0) {};
  std::string addr;
  u_int16_t port;
};


void* syncListener(void* p )
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);
	SOCKETS_NAMESPACE::SocketHandler h;
	SOCKETS_NAMESPACE::ListenSocket<MuxSocket> l(h,true);

	if( l.Bind(param->addr, param->port) )
		pthread_exit(NULL);

	Utility::ResolveLocal(); // resolve local hostname
	h.Add(&l);
	h.Select(1,0);
	while (1) {
		h.Select(1,0);
	}
}

void chrootAndDrop(std::string const& chrootdir, std::string const& username)
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
    cLog.msg(Log::PRIO_NOTICE) << "we are in chroot jail (" << chrootdir << ") now" << std::endl;
    chdir("/");
		if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid)) 
		{
			std::cerr << "can't drop to user " << username << " " << pw->pw_uid << ":" << pw->pw_gid << std::endl;
			exit(-1);
		}
    cLog.msg(Log::PRIO_NOTICE) << "dropped user to " << username << " " << pw->pw_uid << ":" << pw->pw_gid << std::endl;
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
  
//  std::cout << "running in background now..." << std::endl;

  int fd;
//  for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
  for (fd=0;fd<=2;fd++) // close all file descriptors
    close(fd);
  fd=open("/dev/null",O_RDWR);        // stdin
  dup(fd);                            // stdout
  dup(fd);                            // stderr
  umask(027); 
}

int main(int argc, char* argv[])
{
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }
  
  std::ifstream file( gOpt.getFileName().c_str() );
  if( file.is_open() )
    file.close();
  else
  {
    std::cout << "ERROR: unable to open file!" << std::endl;
    exit(-1);
  }

  std::ofstream pidFile;
  if(gOpt.getPidFile() != "") {
    pidFile.open(gOpt.getPidFile().c_str());
    if(!pidFile.is_open()) {
      std::cout << "can't open pid file" << std::endl;
    }
  }
  
  if(gOpt.getChroot())
    chrootAndDrop(gOpt.getChrootDir(), gOpt.getUsername());
  if(gOpt.getDaemonize())
    daemonize();

  if(pidFile.is_open()) {
    pid_t pid = getpid();
    pidFile << pid;
    pidFile.close();
  }

  SignalController sig;
  sig.init();

  ThreadParam p;
  p.addr = gOpt.getBindToAddr();
  p.port = gOpt.getBindToPort(); 
	pthread_t syncListenerThread;
	pthread_create(&syncListenerThread, NULL, syncListener, &p);  

	int ret = sig.run();

	pthread_cancel(syncListenerThread);  
  
	pthread_join(syncListenerThread, NULL);

  return ret;
}

