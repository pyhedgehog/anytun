#ifndef _DAEMON_HPP
#define _DAEMON_HPP
#ifndef NODAEMON

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
    chdir("/");
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
  fd=open("/dev/null",O_RDWR);        // stdin
  dup(fd);                            // stdout
  dup(fd);                            // stderr
  umask(027);
}
#endif
#endif

