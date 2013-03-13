#!/usr/bin/env python
import subprocess
import select
import pwd
import sys
import os

i = subprocess.Popen([ './stdin'],
    stdout = -1,
    )
rd = i.stdout.fileno()

o = subprocess.Popen(['./stdout'],
    stdin  = -1,
    )
wr = o.stdin.fileno()

uid, gid = pwd.getpwnam('nacltaia-otr')[2:4]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setgid(gid)
os.setuid(uid)
del uid, gid

# why doesn't python have pollfd.revents?
poll=select.poll()
poll.register(rd,select.POLLIN|select.POLLPRI)
poll.register(6,select.POLLIN|select.POLLPRI)
poll=poll.poll

client_events=select.poll()
client_events.register(rd,select.POLLIN|select.POLLPRI)
def client_revents():
  return len(client_events.poll(0))

server_events=select.poll()
server_events.register(6,select.POLLIN|select.POLLPRI)
def server_revents():
  return len(server_events.poll(0))

while 1:

  poll(-1)

  if client_revents():
    buffer = os.read(rd,1024)
    if not buffer: sys.exit(0)
    os.write(7,buffer)

  if server_revents():
    buffer = os.read(6,1024)
    if not buffer: sys.exit(0)
    os.write(wr,buffer)
