#ifndef _DAEMON_HPP
#define _DAEMON_HPP
#ifndef NODAEMON

#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

void chrootAndDrop(std::string const& chrootdir, std::string const& username)
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
    cLog.msg(Log::PRIO_NOTICE) << "we are in chroot jail (" << chrootdir << ") now" << std::endl;
    if(chdir("/"))
    {
      std::cerr << "can't change to /" << std::endl;
      exit(-1);
    }
    if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid))
    {
      std::cerr << "can't drop to user " << username << " " << pw->pw_uid << ":" << pw->pw_gid << std::endl;
      exit(-1);
    }
    cLog.msg(Log::PRIO_NOTICE) << "dropped user to " << username << " " << pw->pw_uid << ":" << pw->pw_gid << std::endl;
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
  fd = open("/dev/null",O_RDWR);        // stdin
  if(fd == -1)
    cLog.msg(Log::PRIO_WARNING) << "can't open stdin";
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

