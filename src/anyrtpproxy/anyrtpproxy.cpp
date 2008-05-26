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
#include "portWindow.h"
#include <map>
#include <fstream>

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
  ListenerThreadParam(UDPSocket& s1, UDPSocket& s2, std::string c, int d, SyncQueue& q) : sock1_(s1), sock2_(s2), call_id_(c), 
                                                                                          dir_(d), running_(true), queue_(q)
  {};
  
  UDPSocket& sock1_;
  UDPSocket& sock2_;
  std::string call_id_;
  int dir_;
  bool running_;
  SyncQueue& queue_;
};

void* listener(void* p)
{
  ListenerThreadParam* param = reinterpret_cast<ListenerThreadParam*>(p);
  
  cLog.msg(Log::PRIO_NOTICE) << "listener(" << param->call_id_ << "/" << param->dir_ << ") started";
  
  try 
  {
    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    string remote_addr;
    u_int16_t remote_port;
    while(1) {
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len=0;
      if(param->dir_ == 1)
        len = param->sock1_.recvFromNonBlocking(buf.getBuf(), buf.getLength(), remote_addr, remote_port, 1000);
      else if(param->dir_ == 2)
        len = param->sock2_.recvFromNonBlocking(buf.getBuf(), buf.getLength(), remote_addr, remote_port, 1000);
			else break;

      RtpSession& session = gRtpSessionTable.getSession(param->call_id_);
      if(session.isDead()) {
        cLog.msg(Log::PRIO_NOTICE) << "listener(" << param->call_id_ << "/" << param->dir_ << ") session is dead, exiting"; 
        break;
      }

      if(!len)
        continue;
      buf.setLength(len);
      
      if((param->dir_ == 1 && (remote_port != session.getRemotePort1() || remote_addr != session.getRemoteAddr1())) || 
         (param->dir_ == 2 && (remote_port != session.getRemotePort2() || remote_addr != session.getRemoteAddr2())))
      {
        if(gOpt.getNat() ||
           (!gOpt.getNoNatOnce() && ((param->dir_ == 1 && !session.getSeen1()) || 
                                     (param->dir_ == 2 && !session.getSeen2()))))
        {
          cLog.msg(Log::PRIO_NOTICE) << "listener(" << param->call_id_ << "/" << param->dir_ << ") setting remote host to "
                                     << remote_addr << ":" << remote_port;
          if(param->dir_ == 1) {
            session.setRemotePort1(remote_port);
            session.setRemoteAddr1(remote_addr);
          }
          if(param->dir_ == 2) {
            session.setRemotePort2(remote_port);
            session.setRemoteAddr2(remote_addr);
          }

          if(!gOpt.getNat()) { // with nat enabled sync is not needed
            SyncCommand sc(param->call_id_);
            param->queue_.push(sc);
          }
        }
        else
          continue;
			}
      session.setSeen1();
      session.setSeen2();

      if(param->dir_ == 1)
        param->sock2_.sendTo(buf.getBuf(), buf.getLength(), session.getRemoteAddr2(), session.getRemotePort2());
      else if(param->dir_ == 2)
        param->sock1_.sendTo(buf.getBuf(), buf.getLength(), session.getRemoteAddr1(), session.getRemotePort1());
      else break;
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "listener(" << param->call_id_ << "/" << param->dir_ << ") exiting because: " << e.what();
  }
  param->running_ = false;
  gCallIdQueue.push(param->call_id_);
  pthread_exit(NULL);
}

class ListenerData
{
public:
  ListenerData(ListenerThreadParam lp1, ListenerThreadParam lp2) : param1_(lp1), param2_(lp2)
  {};
  
  UDPSocket* sock1_;
  UDPSocket* sock2_;
  pthread_t thread1_;
  pthread_t thread2_;
  ListenerThreadParam param1_;
  ListenerThreadParam param2_;
};

void* listenerManager(void* p)
{
  SyncQueue* queue_ = reinterpret_cast<SyncQueue*>(p);

  std::map<std::string, ListenerData*> listenerMap;
  while(1)
  {
    try 
    {
      std::string call_id = gCallIdQueue.front(); // waits for semaphor and returns next call_id
      gCallIdQueue.pop();

      RtpSession& session = gRtpSessionTable.getSession(call_id);
      if(!session.isComplete())
        continue;

      std::map<std::string, ListenerData*>::iterator it;
      it = listenerMap.find(call_id);
      if(it == listenerMap.end()) // listener Threads not existing yet
      {
        UDPSocket* sock1 = new UDPSocket(session.getLocalAddr(), session.getLocalPort1());
        UDPSocket* sock2 = new UDPSocket(session.getLocalAddr(), session.getLocalPort2());
        
        ListenerData* ld = new ListenerData(ListenerThreadParam(*sock1, *sock2, call_id, 1, *queue_),
                                            ListenerThreadParam(*sock1, *sock2, call_id, 2, *queue_));
        ld->sock1_ = sock1;
        ld->sock2_ = sock2;
        pthread_create(&(ld->thread1_), NULL, listener, &(ld->param1_));
        pthread_create(&(ld->thread2_), NULL, listener, &(ld->param2_));
        
        std::pair<std::map<std::string, ListenerData*>::iterator, bool> ret;
        ret = listenerMap.insert(std::map<std::string, ListenerData*>::value_type(call_id, ld));
        continue;
      }

      if(!it->second->param1_.running_ && !it->second->param2_.running_)
      {
        cLog.msg(Log::PRIO_NOTICE) << "listenerManager both threads for '" << call_id << "' exited, cleaning up";
        pthread_join(it->second->thread1_, NULL);
        pthread_join(it->second->thread2_, NULL);        
        delete it->second->sock1_;
        delete it->second->sock2_;
        delete it->second;
        listenerMap.erase(it);
        gRtpSessionTable.delSession(call_id);
        continue;
      }
          // TODO: reinit if session changed
    }
    catch(std::exception &e)
    {
      cLog.msg(Log::PRIO_ERR) << "listenerManager restarting after exception: " << e.what();
      usleep(500); // in case of an hard error don't block cpu (this is ugly)
    }
  }
  cLog.msg(Log::PRIO_ERR) << "listenerManager exiting because of unknown reason";
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
//  std::cout << "anyrtpproxy" << std::endl;
  if(!gOpt.parse(argc, argv))
  {
    gOpt.printUsage();
    exit(-1);
  }

  cLog.setLogName("anyrtpproxy");
  cLog.msg(Log::PRIO_NOTICE) << "anyrtpproxy started...";

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

  SyncQueue queue;

  pthread_t listenerManagerThread;
  pthread_create(&listenerManagerThread, NULL, listenerManager, &queue);
  pthread_detach(listenerManagerThread);

  pthread_t syncListenerThread;

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

	PortWindow port_window(gOpt.getRtpStartPort(),gOpt.getRtpEndPort());
  CommandHandler cmd(queue, gOpt.getControlInterface().addr_, gOpt.getControlInterface().port_,port_window);
  
  int ret = sig.run();
  return ret;
}

