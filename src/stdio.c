#include <stdlib.h>
#include <poll.h>
#include <pwd.h>

main()
{

  int stdin_pid;
  int stdin_out[2];

  if (pipe(stdin_out)<0) exit(1);
  stdin_pid = fork();
  if (!stdin_pid)
  {
    close(1);
    dup(stdin_out[1]);
    close(stdin_out[0]);
    close(stdin_out[1]);
    execvp("./stdin",("./stdin",'\x00'));
  } else {
    if (stdin_pid<0) exit(2);
  } close(stdin_out[1]);

  int stdout_pid;
  int stdout_in[2];

  if (pipe(stdout_in)<0) exit(3);
  stdout_pid = fork();
  if (!stdout_pid)
  {
    close(0);
    dup(stdout_in[0]);
    close(stdout_in[0]);
    close(stdout_in[1]);
    execvp("./stdout",("./stdout",'\x00'));
  } else {
    if (stdout_pid<0) exit(4);
  } close(stdout_in[0]);

  if (chdir("crypto/")) exit(64);
  struct passwd *nacltaia_otr = getpwnam("nacltaia-otr");
  if ((!nacltaia_otr) || ((chroot(getenv("PWD"))) || (setgid(nacltaia_otr->pw_gid)) || (setuid(nacltaia_otr->pw_uid)))) exit(64);

  struct pollfd fds[2];
  fds[0].fd = stdin_out[0];
  fds[0].events = POLLIN | POLLPRI;
  fds[1].fd = 6;
  fds[1].events = POLLIN | POLLPRI;

  unsigned char buffer[1024];

  while (1)
  {
    poll(fds,2,-1);
    if (fds[0].revents) if (write(7,buffer,read(stdin_out[0],buffer,1024))<1) exit(5);
    if (fds[1].revents) if (write(stdout_in[1],buffer,read(6,buffer,1024))<1) exit(6);
  }

}
