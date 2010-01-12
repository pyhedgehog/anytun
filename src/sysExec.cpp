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
 *  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl, 
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
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <boost/bind.hpp>
#include <boost/thread.hpp>

#include "datatypes.h"
#include "sysExec.h"
#include "log.h"
#include "anytunError.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>

SysExec::SysExec(std::string const& script) : script_(script),closed_(false),return_code_(0)
{
  doExec(script, StringVector(), StringList());
}

SysExec::SysExec(std::string const& script, StringVector const& args) : script_(script),closed_(false),return_code_(0)
{
  doExec(script, args, StringList());
}

SysExec::SysExec(std::string const& script, StringList const& env) : script_(script),closed_(false),return_code_(0)
{
  doExec( script, StringVector(), env);
}

SysExec::SysExec(std::string const& script, StringVector const& args, StringList const& env) : script_(script),closed_(false),return_code_(0)
{
  doExec( script, args, env);
}

SysExec::~SysExec()
{
  if(!closed_)
    close(pipefd_);
}

void SysExec::doExec(std::string const& script, StringVector const& args, StringList const& env)
{
  int pipefd[2];
  if(pipe(pipefd) == -1) {
    cLog.msg(Log::PRIO_ERROR) << "executing script '" << script << "' pipe() error: " << AnytunErrno(errno);
    return;
  }

  pid_ = fork();
  if(pid_ == -1) {
    cLog.msg(Log::PRIO_ERROR) << "executing script '" << script << "' fork() error: " << AnytunErrno(errno);
    return;
  }

  if(pid_) {
    close(pipefd[1]);
		pipefd_=pipefd[0];
    //boost::thread(boost::bind(waitForScript, script, pid, pipefd[0]));
    return;
  }
// child code
  int fd;
  for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
    if(fd != pipefd[1]) close(fd);
  
  fd = open("/dev/null",O_RDWR);        // stdin
  if(fd == -1)
    cLog.msg(Log::PRIO_WARNING) << "can't open stdin";
  else {
    if(dup(fd) == -1)   // stdout
      cLog.msg(Log::PRIO_WARNING) << "can't open stdout";
    if(dup(fd) == -1)   // stderr
      cLog.msg(Log::PRIO_WARNING) << "can't open stderr";
  }
  
  char** argv = new char*[args.size() + 2];
  argv[0] = new char[script.size() + 1];
  std::strcpy(argv[0], script.c_str());
  for(unsigned int i=0; i<args.size(); ++i) {
    argv[i+1] = new char[args[i].size() + 1];
    std::strcpy(argv[i+1], args[i].c_str());
  }
  argv[args.size() + 1] = NULL;

  char** evp;
  evp = new char*[env.size() + 1];
  unsigned int i = 0;
  for(StringList::const_iterator it = env.begin(); it != env.end(); ++it) {
    evp[i] = new char[it->size() + 1];
    std::strcpy(evp[i], it->c_str());
    ++i;
  }
  evp[env.size()] = NULL;
  
  execve(script.c_str(), argv, evp);
      // if execve returns, an error occurred, but logging doesn't work 
      // because we closed all file descriptors, so just write errno to
      // pipe and call exit
  int err = errno;
  int ret = write(pipefd[1], (void*)(&err), sizeof(err));
  if(ret != sizeof(errno))
    exit(-2);
  exit(-1);
}

int SysExec::waitForScript()
{
  int status = 0;
  waitpid(pid_, &status, 0);

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(pipefd_, &rfds);
  struct timeval tv = { 0 , 0 };
  if(select(pipefd_+1, &rfds, NULL, NULL, &tv) == 1) {
    int err = 0;
    if(read(pipefd_, (void*)(&err), sizeof(err)) >= static_cast<int>(sizeof(err))) {
      cLog.msg(Log::PRIO_NOTICE) << "script '" << script_ << "' exec() error: " << AnytunErrno(err);
      close(pipefd_);
      return -1;
    }
  }
  if(WIFEXITED(status))
    cLog.msg(Log::PRIO_NOTICE) << "script '" << script_ << "' returned " << WEXITSTATUS(status);  
  else if(WIFSIGNALED(status))
    cLog.msg(Log::PRIO_NOTICE) << "script '" << script_ << "' terminated after signal " << WTERMSIG(status);
  else
    cLog.msg(Log::PRIO_ERROR) << "executing script '" << script_ << "': unknown error";

  close(pipefd_);
	closed_=true;

  return_code_ = status;

  return status;
}

int SysExec::getReturnCode() const 
{
  return return_code_;
}

void SysExec::waitAndDestroy(SysExec*& s)
{
  if(!s)
    return;

  s->waitForScript();
  delete(s);
  s = NULL;
}
