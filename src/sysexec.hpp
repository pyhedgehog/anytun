#ifndef _SYSEXEC_HPP
#define _SYSEXEC_HPP
#ifndef NOEXEC

int execScript(std::string const& script, std::string const& ifname)
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
    return execl("/bin/sh", "/bin/sh", script.c_str(), ifname.c_str(), NULL);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return status;
}


#endif
#endif

