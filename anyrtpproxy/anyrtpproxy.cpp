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
 *  Copyright (C) 2007 anytun.org <satp@wirdorange.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <iostream>

#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "../datatypes.h"

#include "../log.h"
#include "../signalController.h"
#include "../PracticalSocket.h"
#include "../buffer.h"
#include "connectionList.h"
#include "../rtpSessionTable.h"
#include "../syncCommand.h"
#include "../syncQueue.h"
#include "../syncSocketHandler.h"
#include "../syncListenSocket.h"

#include "../syncSocket.h"
#include "../syncClientSocket.h"
#include "../threadUtils.hpp"

#include "commandHandler.h"
#include "callIdQueue.h"

#include "options.h"
#include <map>


#define MAX_PACKET_SIZE 1500


class ThreadParam
{
public:
  ThreadParam(SyncQueue & queue_,OptionConnectTo & connto_)
    : queue(queue_),connto(connto_)
    {};
  SyncQueue & queue;
  OptionConnectTo & connto;
};

class ListenerThreadParam
{
public:
  ListenerThreadParam(UDPSocket& s1, UDPSocket& s2, std::string c, int d) : sock1_(s1), sock2_(s2), call_id_(c), dir_(d)
  {};
  
  UDPSocket& sock1_;
  UDPSocket& sock2_;
  std::string call_id_;
  int dir_;
};

void* listener(void* p)
{
  ListenerThreadParam* param = reinterpret_cast<ListenerThreadParam*>(p);
  
  cLog.msg(Log::PRIO_ERR) << "listener(" << param->call_id_ << "/" << param->dir_ << ") started";
  
  try 
  {
    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    string remote_addr;
    u_int16_t remote_port;
    while(1) {
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len;
      if(param->dir_ == 1)
        len = param->sock1_.recvFrom(buf.getBuf(), buf.getLength(), remote_addr, remote_port);
      else if(param->dir_ == 2)
        len = param->sock2_.recvFrom(buf.getBuf(), buf.getLength(), remote_addr, remote_port);
      buf.setLength(len);

      RtpSession& session = gRtpSessionTable.getSession(param->call_id_);
      if(session.isDead())
        break;

          //TODO: if weak? don't check but save the new(?) remote addr into list
      if((param->dir_ == 1 && (remote_port != session.getRemotePort1() || remote_addr != session.getRemoteAddr1())) || 
         (param->dir_ == 2 && (remote_port != session.getRemotePort2() || remote_addr != session.getRemoteAddr2())))
        continue;

      if(param->dir_ == 1)
        param->sock2_.sendTo(buf.getBuf(), buf.getLength(), session.getRemoteAddr2(), session.getRemotePort2());
      else if(param->dir_ == 2)
        param->sock1_.sendTo(buf.getBuf(), buf.getLength(), session.getRemoteAddr1(), session.getRemotePort1());
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "listener(" << param->call_id_ << "/" << param->dir_ << ") exiting because: " << e.what();
  }
  cLog.msg(Log::PRIO_ERR) << "listener(" << param->call_id_ << "/" << param->dir_ << ") exiting normally";

  pthread_exit(NULL);
}

class ListenerData
{
public:
  ListenerData(ListenerThreadParam lp1, ListenerThreadParam lp2) : params1_(lp1), params2_(lp2)
  {};
  
  UDPSocket* sock1_;
  UDPSocket* sock2_;
  pthread_t threads1_;
  pthread_t threads2_;
  ListenerThreadParam params1_;
  ListenerThreadParam params2_;
};

void* listenerManager(void* dont_use_me)
{
  try 
  {
    std::map<std::string, ListenerData> listenerMap;
    while(1)
    {
      std::string call_id = gCallIdQueue.front(); // waits for semaphor and returns next call_id
      gCallIdQueue.pop();

      RtpSession& session = gRtpSessionTable.getSession(call_id);
      if(!session.isComplete())
        continue;

      std::map<std::string, ListenerData>::iterator it;
      it = listenerMap.find(call_id);
      if(it == listenerMap.end()) // listener Threads not existing yet
      {
        cLog.msg(Log::PRIO_ERR) << "listenerManager: open UDP Socket: " 
                                << session.getLocalAddr() << ":" << session.getLocalPort1() << " "
                                << session.getLocalAddr() << ":" << session.getLocalPort2();
        
        UDPSocket* sock1 = new UDPSocket(session.getLocalAddr(), session.getLocalPort1());
        UDPSocket* sock2 = new UDPSocket(session.getLocalAddr(), session.getLocalPort2());
        
        ListenerData ld(ListenerThreadParam(*sock1, *sock2, call_id, 1),
                        ListenerThreadParam(*sock1, *sock2, call_id, 2));
        ld.sock1_ = sock1;
        ld.sock2_ = sock2;
        pthread_create(&(ld.threads1_), NULL, listener, &(ld.params1_));
        pthread_create(&(ld.threads2_), NULL, listener, &(ld.params2_));
        
        std::pair<std::map<std::string, ListenerData>::iterator, bool> ret;
        ret = listenerMap.insert(std::map<std::string, ListenerData>::value_type(call_id, ld));
        it = ret.first;
        continue;
      }
          // TODO: reinit if session is changed or cleanup if it is daed
    }
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "listenerManager exiting because: " << e.what();
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

void* syncConnector(void* p )
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

  SocketHandler h;
	ConnectionList cl;
  SyncClientSocket sock(h,cl);
  sock.Open( param->connto.host, param->connto.port);
  h.Add(&sock);
  while (h.GetCount())
  {
    h.Select();
  }
  pthread_exit(NULL);
}

void* syncListener(void* p )
{
  ThreadParam* param = reinterpret_cast<ThreadParam*>(p);
	ConnectionList cl;

  SyncSocketHandler h(param->queue);
  SyncListenSocket<SyncSocket,ConnectionList> l(h,cl);

  if (l.Bind(gOpt.getLocalSyncPort()))
    pthread_exit(NULL);

  Utility::ResolveLocal(); // resolve local hostname
  h.Add(&l);
  h.Select(1,0);
  while (1) {
    h.Select(1,0);
  }
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

  pthread_t listenerManagerThread;
  pthread_create(&listenerManagerThread, NULL, listenerManager, NULL);
  pthread_detach(listenerManagerThread);

  pthread_t syncListenerThread;

  SyncQueue queue;
	ConnectToList connect_to = gOpt.getConnectTo();
	ThreadParam p( queue,*(new OptionConnectTo()));
  if ( gOpt.getLocalSyncPort())
    pthread_create(&syncListenerThread, NULL, syncListener, &p);

  std::list<pthread_t> connectThreads;
  for(ConnectToList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it)
  {
    connectThreads.push_back(pthread_t());
    ThreadParam * point = new ThreadParam(queue,*it);
    pthread_create(& connectThreads.back(),  NULL, syncConnector, point);
  }

  CommandHandler cmd(queue, gOpt.getControlInterface().addr_, gOpt.getControlInterface().port_);
  
  int ret = sig.run();
  return ret;
}

