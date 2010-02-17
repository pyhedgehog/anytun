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
#pragma once
#ifndef ANYTUN_sysexec_hpp_INCLUDED
#define ANYTUN_sysexec_hpp_INCLUDED

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>

SysExec::~SysExec()
{
  if(!closed_) {
    close(pipefd_);
  }
}


template<class T>
char** dupSysStringArray(T const& array)
{
  char** new_array;
  new_array = static_cast<char**>(malloc((array.size() + 1)*sizeof(char*)));
  if(!new_array) {
    return NULL;
  }

  unsigned int i = 0;
  for(typename T::const_iterator it = array.begin(); it != array.end(); ++it) {
    new_array[i] = strdup(it->c_str());
    if(!new_array) {
      while(i--) {
        free(new_array[i]);
      }
      free(new_array);
      return NULL;
    }
    ++i;
  }
  new_array[array.size()] = NULL;
  return new_array;
}

void freeSysStringArray(char** array)
{
  if(!array) {
    return;
  }

  for(int i=0; array[i] ; ++i) {
    free(array[i]);
  }

  free(array);
}

void SysExec::doExec(StringVector args, StringList env)
{
  int pipefd[2];
  if(pipe(pipefd) == -1) {
    cLog.msg(Log::PRIO_ERROR) << "executing script '" << script_ << "' pipe() error: " << AnytunErrno(errno);
    return;
  }

  pid_ = fork();
  if(pid_ == -1) {
    cLog.msg(Log::PRIO_ERROR) << "executing script '" << script_ << "' fork() error: " << AnytunErrno(errno);
    return;
  }

  if(pid_) {
    close(pipefd[1]);
    pipefd_=pipefd[0];
    // parent exits here, call waitForScript to cleanup up zombie
    return;
  }
  // child code, exec the script
  int fd;
  for(fd=getdtablesize(); fd>=0; --fd) // close all file descriptors
    if(fd != pipefd[1]) { close(fd); }

  fd = open("/dev/null",O_RDWR);        // stdin
  if(fd == -1) {
    cLog.msg(Log::PRIO_WARNING) << "can't open stdin";
  } else {
    if(dup(fd) == -1) { // stdout
      cLog.msg(Log::PRIO_WARNING) << "can't open stdout";
    }
    if(dup(fd) == -1) { // stderr
      cLog.msg(Log::PRIO_WARNING) << "can't open stderr";
    }
  }

  args.insert(args.begin(), script_);
  char** argv = dupSysStringArray(args);
  char** evp = dupSysStringArray(env);

  execve(script_.c_str(), argv, evp);
  // if execve returns, an error occurred, but logging doesn't work
  // because we closed all file descriptors, so just write errno to
  // pipe and call exit

  freeSysStringArray(argv);
  freeSysStringArray(evp);

  int err = errno;
  int ret = write(pipefd[1], (void*)(&err), sizeof(err));
  if(ret != sizeof(errno)) {
    exit(-2);
  }
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
      cLog.msg(Log::PRIO_ERROR) << "script '" << script_ << "' exec() error: " << AnytunErrno(err);
      close(pipefd_);
      return_code_ = -1;
      return return_code_;
    }
  }

  close(pipefd_);
  closed_ = true;
  return_code_ = status;

  return return_code_;
}

void SysExec::waitAndDestroy(SysExec*& s)
{
  if(!s) {
    return;
  }

  s->waitForScript();
  if(WIFEXITED(s->return_code_)) {
    cLog.msg(Log::PRIO_NOTICE) << "script '" << s->script_ << "' returned " << WEXITSTATUS(s->return_code_);
  } else if(WIFSIGNALED(s->return_code_)) {
    cLog.msg(Log::PRIO_NOTICE) << "script '" << s->script_ << "' terminated after signal " << WTERMSIG(s->return_code_);
  } else if(WIFSTOPPED(s->return_code_)) {
    cLog.msg(Log::PRIO_NOTICE) << "script '" << s->script_ << "' stopped after signal " << WSTOPSIG(s->return_code_);
  } else if(WIFCONTINUED(s->return_code_)) {
    cLog.msg(Log::PRIO_NOTICE) << "script '" << s->script_ << "' continued after SIGCONT";
  }

  delete(s);
  s = NULL;
}

#endif // ANYTUN_sysexec_hpp_INCLUDED
