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

#ifndef _SYSEXEC_HPP
#define _SYSEXEC_HPP
#ifndef NO_EXEC

int execScript(std::string const& script, std::string const& ifname, std::string const& ifnode)
{
  pid_t pid;
  pid = fork();
  if(!pid) {
    int fd;
    for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
      close(fd);

    fd = open("/dev/null",O_RDWR);        // stdin
    if(fd == -1)
      cLog.msg(Log::PRIO_WARNING) << "can't open stdin";
    else {
      if(dup(fd) == -1)   // stdout
        cLog.msg(Log::PRIO_WARNING) << "can't open stdout";
      if(dup(fd) == -1)   // stderr
        cLog.msg(Log::PRIO_WARNING) << "can't open stderr";
    }
    execl("/bin/sh", "/bin/sh", script.c_str(), ifname.c_str(), ifnode.c_str(), (char*)NULL);
        // if execl return, an error occurred
    cLog.msg(Log::PRIO_ERR) << "error on executing script: " << LogErrno(errno);
    return -1;
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if(WIFEXITED(status))
    cLog.msg(Log::PRIO_NOTICE) << "script '" << script << "' returned " << WEXITSTATUS(status);  
  if(WIFSIGNALED(status))
    cLog.msg(Log::PRIO_NOTICE) << "script '" << script << "' terminated after signal " << WTERMSIG(status);

  return status;
}


#endif
#endif

