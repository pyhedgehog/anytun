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

#ifndef _DAEMON_HPP
#define _DAEMON_HPP
#ifndef NO_DAEMON

#include <sstream>

#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"

#ifndef NO_PRIVDROP
class PrivInfo
{
public:
  PrivInfo(std::string const& username, std::string const& groupname)
  {
    pw_ = NULL;
    gr_ = NULL;
    
    if(username == "")
      return;

    pw_ = getpwnam(username.c_str());
    if(!pw_)
      throw std::runtime_error("unkown user " + username);
    
    if(groupname != "")
      gr_ = getgrnam(groupname.c_str());
    else
      gr_ = getgrgid(pw_->pw_gid);
    
    if(!gr_)
      throw std::runtime_error("unkown group " + groupname);
  }

  void drop()
  {
    if(!pw_ || !gr_)
      return;

    if(setgid(gr_->gr_gid)) {
      std::stringstream msg;
      msg << "setgid('" << gr_->gr_name << "') failed: " << LogErrno(errno);
      throw std::runtime_error(msg.str());
    }
    
    gid_t gr_list[1];
    gr_list[0] = gr_->gr_gid;
    if(setgroups (1, gr_list)) {
      std::stringstream msg;
      msg << "setgroups(['" << gr_->gr_name << "']) failed: " << LogErrno(errno);
      throw std::runtime_error(msg.str());
    }
    
    if(setuid(pw_->pw_uid)) {
      std::stringstream msg;
      msg << "setuid('" << pw_->pw_name << "') failed: " << LogErrno(errno);
      throw std::runtime_error(msg.str());
    }
    
    cLog.msg(Log::PRIO_NOTICE) << "dropped privileges to " << pw_->pw_name << ":" << gr_->gr_name;
  }

private:
  struct passwd* pw_;
  struct group* gr_;
};
#endif

void do_chroot(std::string const& chrootdir)
{
  if (getuid() != 0)
    throw std::runtime_error("this programm has to be run as root in order to run in a chroot");

  if(chroot(chrootdir.c_str()))
    throw std::runtime_error("can't chroot to " + chrootdir);

  cLog.msg(Log::PRIO_NOTICE) << "we are in chroot jail (" << chrootdir << ") now" << std::endl;
  if(chdir("/"))
    throw std::runtime_error("can't change to /");
}

void daemonize()
{
  pid_t pid;

  pid = fork();
  if(pid < 0) {
    std::stringstream msg;
    msg << "daemonizing failed at fork(): " << LogErrno(errno) << ", exitting";
    throw std::runtime_error(msg.str());
  }
  if(pid) exit(0);

  umask(0);

  if(setsid() < 0) {
    std::stringstream msg;
    msg << "daemonizing failed at setsid(): " << LogErrno(errno) << ", exitting";
    throw std::runtime_error(msg.str());
  }

  pid = fork();
  if(pid < 0) {
    std::stringstream msg;
    msg << "daemonizing failed at fork(): " << LogErrno(errno) << ", exitting";
    throw std::runtime_error(msg.str());
  }
  if(pid) exit(0);

  if ((chdir("/")) < 0) {
    std::stringstream msg;
    msg << "daemonizing failed at chdir(): " << LogErrno(errno) << ", exitting";
    throw std::runtime_error(msg.str());
  }

//  std::cout << "running in background now..." << std::endl;

  int fd;
//  for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
  for (fd=0;fd<=2;fd++) // close all file descriptors
    close(fd);
  fd = open("/dev/null",O_RDWR);        // stdin
  if(fd == -1)
    cLog.msg(Log::PRIO_WARNING) << "can't open stdin (chroot and no link to /dev/null?)";
  else {
    if(dup(fd) == -1)   // stdout
      cLog.msg(Log::PRIO_WARNING) << "can't open stdout";
    if(dup(fd) == -1)   // stderr
      cLog.msg(Log::PRIO_WARNING) << "can't open stderr";
  }
  umask(027);
}
#endif
#endif

