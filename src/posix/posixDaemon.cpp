/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Markus Grüneis, Othmar Gsenger, Erwin Nindl,
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Anytun.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include "daemonService.h"
#include "log.h"
#include "options.h"
#include "anytunError.h"

DaemonService::DaemonService() : pw_(NULL), gr_(NULL), daemonized_(false)
{
}

void DaemonService::initPrivs(std::string const& username, std::string const& groupname)
{
  if(username == "") {
    return;
  }

  pw_ = getpwnam(username.c_str());
  if(!pw_) {
    AnytunError::throwErr() << "unknown user " << username;
  }

  if(groupname != "") {
    gr_ = getgrnam(groupname.c_str());
  } else {
    gr_ = getgrgid(pw_->pw_gid);
  }

  if(!gr_) {
    AnytunError::throwErr() << "unknown group " << groupname;
  }
}

void DaemonService::dropPrivs()
{
  if(!pw_ || !gr_) {
    return;
  }

  if(setgid(gr_->gr_gid)) {
    AnytunError::throwErr() << "setgid('" << gr_->gr_name << "') failed: " << AnytunErrno(errno);
  }

  gid_t gr_list[1];
  gr_list[0] = gr_->gr_gid;
  if(setgroups(1, gr_list)) {
    AnytunError::throwErr() << "setgroups(['" << gr_->gr_name << "']) failed: " << AnytunErrno(errno);
  }

  if(setuid(pw_->pw_uid)) {
    AnytunError::throwErr() << "setuid('" << pw_->pw_name << "') failed: " << AnytunErrno(errno);
  }

  cLog.msg(Log::PRIO_NOTICE) << "dropped privileges to " << pw_->pw_name << ":" << gr_->gr_name;
}

void DaemonService::chroot(std::string const& chrootdir)
{
  if(getuid() != 0) {
    AnytunError::throwErr() << "this program has to be run as root in order to run in a chroot";
  }

  if(::chroot(chrootdir.c_str())) {
    AnytunError::throwErr() << "can't chroot to " << chrootdir;
  }

  cLog.msg(Log::PRIO_NOTICE) << "we are in chroot jail (" << chrootdir << ") now" << std::endl;
  if(chdir("/")) {
    AnytunError::throwErr() << "can't change to /";
  }
}

/// TODO: this outstandignly ugly please and i really can't stress the please fix it asap!!!!!!!

std::ofstream pidFile; // FIXXXME no global variable

void DaemonService::daemonize()
{
  //  std::ofstream pidFile;
  if(gOpt.getPidFile() != "") {
    pidFile.open(gOpt.getPidFile().c_str());
    if(!pidFile.is_open()) {
      AnytunError::throwErr() << "can't open pid file (" << gOpt.getPidFile() << "): " << AnytunErrno(errno);
    }
  }

  pid_t pid;

  pid = fork();
  if(pid < 0) {
    AnytunError::throwErr() << "daemonizing failed at fork(): " << AnytunErrno(errno) << ", exitting";
  }

  if(pid) { exit(0); }

  umask(0);

  if(setsid() < 0) {
    AnytunError::throwErr() << "daemonizing failed at setsid(): " << AnytunErrno(errno) << ", exitting";
  }

  pid = fork();
  if(pid < 0) {
    AnytunError::throwErr() << "daemonizing failed at fork(): " << AnytunErrno(errno) << ", exitting";
  }

  if(pid) { exit(0); }

  if((chdir("/")) < 0) {
    AnytunError::throwErr() << "daemonizing failed at chdir(): " << AnytunErrno(errno) << ", exitting";
  }

  //  std::cout << "running in background now..." << std::endl;

  int fd;
  //  for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
  for(fd=0; fd<=2; fd++) { // close all file descriptors
    close(fd);
  }
  fd = open("/dev/null",O_RDWR);        // stdin
  if(fd == -1) {
    cLog.msg(Log::PRIO_WARNING) << "can't open /dev/null as stdin";
  } else {
    if(dup(fd) == -1) { // stdout
      cLog.msg(Log::PRIO_WARNING) << "can't open /dev/null as stdout";
    }
    if(dup(fd) == -1) { // stderr
      cLog.msg(Log::PRIO_WARNING) << "can't open /dev/null as stderr";
    }
  }

  // FIXXXXME: write this pid to file (currently pid from posix/signhandler.hpp:77 is used)
  //
  //   if(pidFile.is_open()) {
  //     pid_t pid = getpid();
  //     pidFile << pid;
  //     pidFile.close();
  //   }

  daemonized_ = true;
}

bool DaemonService::isDaemonized()
{
  return daemonized_;
}
