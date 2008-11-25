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

#include <boost/asio.hpp>

#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "../datatypes.h"

#include "../log.h"
#include "../signalController.h"
#include "../buffer.h"
#include "connectionList.h"
#include "../rtpSessionTable.h"
#include "../syncCommand.h"
#include "../syncQueue.h"
#include "../syncClient.h"
//#include "../syncOnConnect.h"

#include "../threadUtils.hpp"

#include "commandHandler.h"
#include "callIdQueue.h"

#include "options.h"
#include "portWindow.h"
#include <map>
#include <fstream>

#define MAX_PACKET_SIZE 1500

typedef boost::asio::ip::udp rtp_proto;

void listener(rtp_proto::socket* sock1, rtp_proto::socket* sock2, std::string call_id, int dir, SyncQueue* queue, bool* running)
{
  cLog.msg(Log::PRIO_NOTICE) << "listener(" << call_id << "/" << dir << ") started";

  try 
  {
    Buffer buf(u_int32_t(MAX_PACKET_SIZE));
    rtp_proto::endpoint remote_end;

    while(1) {
      buf.setLength(MAX_PACKET_SIZE);
      u_int32_t len=0;
      if(dir == 1)
        len = 0;//sock1->recvFromNonBlocking(buf.getBuf(), buf.getLength(), remote_end, 1000);
      else if(dir == 2)
        len = 0; //sock2->recvFromNonBlocking(buf.getBuf(), buf.getLength(), remote_end, 1000);
			else break;

      RtpSession& session = gRtpSessionTable.getSession(call_id);
      if(session.isDead()) {
        cLog.msg(Log::PRIO_NOTICE) << "listener(" << call_id << "/" << dir << ") session is dead, exiting"; 
        break;
      }

      if(!len)
        continue;
      buf.setLength(len);
      
//       if((dir == 1 && remote_end != session.getRemoteEnd1()) || 
//          (dir == 2 && remote_end != session.getRemoteEnd2()))
      {
        if(gOpt.getNat() ||
           (!gOpt.getNoNatOnce() && ((dir == 1 && !session.getSeen1()) || 
                                     (dir == 2 && !session.getSeen2()))))
        {
          cLog.msg(Log::PRIO_NOTICE) << "listener(" << call_id << "/" << dir << ") setting remote host to "
                                     << remote_end;
//           if(dir == 1)
//             session.setRemoteEnd1(remote_end);
//           if(dir == 2)
//             session.setRemoteEnd2(remote_end);

          if(!gOpt.getNat()) { // with nat enabled sync is not needed
            SyncCommand sc(call_id);
            queue->push(sc);
          }
        }
        else
          continue;
			}
      session.setSeen1();
      session.setSeen2();

//       if(dir == 1)
//         sock2->send_to(boost::asio::buffer(buf.getBuf(), buf.getLength()), session.getRemoteEnd2());
//       else if(dir == 2)
//         sock1->send_to(boost::asio::buffer(buf.getBuf(), buf.getLength()), session.getRemoteEnd1());
//       else break;
    }  
  }
  catch(std::exception &e)
  {
    cLog.msg(Log::PRIO_ERR) << "listener(" << call_id << "/" << dir << ") exiting because: " << e.what();
  }
  *running = false;
  gCallIdQueue.push(call_id);
}

class ListenerData
{
public:
  ListenerData()
  {
    ios1_ = new boost::asio::io_service();
    sock1_ = new rtp_proto::socket(*ios1_);
    ios2_ = new boost::asio::io_service();
    sock2_ = new rtp_proto::socket(*ios2_);
  }
  ~ListenerData()
  {
    if(sock1_) delete sock1_;
    if(ios1_) delete ios1_;
    if(sock2_) delete sock2_;
    if(ios2_) delete ios2_;
  }

  boost::asio::io_service* ios1_;
  boost::asio::io_service* ios2_;
  rtp_proto::socket* sock1_;
  rtp_proto::socket* sock2_;
  boost::thread* thread1_;
  boost::thread* thread2_;
  bool running1_;
  bool running2_;
};

void listenerManager(void* p)
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
        ListenerData* ld = new ListenerData();

        rtp_proto::resolver resolver1(*(ld->ios1_));
        rtp_proto::resolver::query query1(session.getLocalAddr(), session.getLocalPort1());  
        rtp_proto::endpoint e1 = *resolver1.resolve(query1);
        ld->sock1_->open(e1.protocol());
        ld->sock1_->bind(e1);

        rtp_proto::resolver resolver2(*(ld->ios2_));
        rtp_proto::resolver::query query2(session.getLocalAddr(), session.getLocalPort2());  
        rtp_proto::endpoint e2 = *resolver2.resolve(query2);
        ld->sock2_->open(e2.protocol());
        ld->sock2_->bind(e2);

        ld->thread1_ = new boost::thread(boost::bind(listener, ld->sock1_, ld->sock2_, call_id, 1, queue_, &(ld->running1_)));
        ld->thread2_ = new boost::thread(boost::bind(listener, ld->sock1_, ld->sock2_, call_id, 2, queue_, &(ld->running2_)));

        std::pair<std::map<std::string, ListenerData*>::iterator, bool> ret;
        ret = listenerMap.insert(std::map<std::string, ListenerData*>::value_type(call_id, ld));
        continue;
      }

      if(!it->second->running1_ && !it->second->running2_)
      {
        cLog.msg(Log::PRIO_NOTICE) << "listenerManager both threads for '" << call_id << "' exited, cleaning up";
        if(it->second->thread1_) {
          it->second->thread1_->join();
          delete it->second->thread1_;
        }
        if(it->second->thread2_) {
          it->second->thread2_->join();
          delete it->second->thread2_;
        }
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

class ThreadParam
{
public:
  ThreadParam(SyncQueue & queue_,OptionConnectTo & connto_)
    : queue(queue_),connto(connto_)
    {};
  SyncQueue & queue;
  OptionConnectTo & connto;
};

void syncConnector(void* p)
{
	ThreadParam* param = reinterpret_cast<ThreadParam*>(p);

	SyncClient sc ( param->connto.host, param->connto.port);
	sc.run();
}

void syncListener(SyncQueue * queue)
{
  try
  {
    boost::asio::io_service io_service;
		SyncTcpConnection::proto::resolver resolver(io_service);
		SyncTcpConnection::proto::endpoint e;
		if(gOpt.getLocalSyncAddr()!="")
		{
			SyncTcpConnection::proto::resolver::query query(gOpt.getLocalSyncAddr(), gOpt.getLocalSyncPort());
			e = *resolver.resolve(query);
		} else {
			SyncTcpConnection::proto::resolver::query query(gOpt.getLocalSyncPort());
			e = *resolver.resolve(query);
		}


    SyncServer server(io_service,e);
//		server.onConnect=boost::bind(syncOnConnect,_1);
		queue->setSyncServerPtr(&server);
    io_service.run();
  }
  catch (std::exception& e)
  {
    std::string addr = gOpt.getLocalSyncAddr() == "" ? "*" : gOpt.getLocalSyncAddr();
    cLog.msg(Log::PRIO_ERR) << "sync: cannot bind to " << addr << ":" << gOpt.getLocalSyncPort()
                            << " (" << e.what() << ")" << std::endl;
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


  boost::thread listenerManagerThread(boost::bind(listenerManager,&queue));


// #ifndef ANYTUN_NOSYNC
//     boost::thread * syncListenerThread;
//     if(gOpt.getLocalSyncPort() != "")
//       syncListenerThread = new boost::thread(boost::bind(syncListener,&queue));
    
//     std::list<boost::thread *> connectThreads;
//     for(ConnectToList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it) { 
//       ThreadParam * point = new ThreadParam(dev, *src, cl, queue,*it);
//       connectThreads.push_back(new boost::thread(boost::bind(syncConnector,point)));
//     }
// #endif



//   pthread_t syncListenerThread;

// 	ConnectToList connect_to = gOpt.getConnectTo();
// 	ThreadParam p( queue,*(new OptionConnectTo()));
//   if ( gOpt.getLocalSyncPort())
//     pthread_create(&syncListenerThread, NULL, syncListener, &p);

//   std::list<pthread_t> connectThreads;
//   for(ConnectToList::iterator it = connect_to.begin() ;it != connect_to.end(); ++it)
//   {
//     connectThreads.push_back(pthread_t());
//     ThreadParam * point = new ThreadParam(queue,*it);
//     pthread_create(& connectThreads.back(),  NULL, syncConnector, point);
//   }

	PortWindow port_window(gOpt.getRtpStartPort(),gOpt.getRtpEndPort());
  CommandHandler cmd(queue, gOpt.getControlInterface().addr_, gOpt.getControlInterface().port_,port_window);
  
  int ret = sig.run();
  return ret;
}

