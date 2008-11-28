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
    fd=open("/dev/null",O_RDWR);        // stdin
    dup(fd);                            // stdout
    dup(fd);                            // stderr
    return execl("/bin/sh", "/bin/sh", script.c_str(), ifname.c_str(), NULL);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return status;
}


#endif
#endif

