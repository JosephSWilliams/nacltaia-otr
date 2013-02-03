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

uid = pwd.getpwnam('nacltaia-otr')[2]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setuid(uid)
del uid

client_POLLIN=select.poll()
client_POLLIN.register(rd,3)

server_POLLIN=select.poll()
server_POLLIN.register(6,3)

def client_poll():
  return len( client_POLLIN.poll(256-
    (256*len( server_POLLIN.poll(0)))
  ))

def server_poll():
  return len( server_POLLIN.poll(256-
    (256*len( client_POLLIN.poll(0)))
  ))

while 1:

  if client_poll():
    buffer = str()
    while 1:
      byte = os.read(rd,1)
      if not byte:
        sys.exit(0)
      if byte == '\n':
        break
      if byte != '\r' and len(buffer)<1024:
        buffer+=byte
    os.write(7,buffer+'\n')

  while server_poll():
    buffer = str()
    while 1:
      byte = os.read(6,1)
      if not byte:
        sys.exit(0)
      if byte == '\n':
        break
      if byte != '\r' and len(buffer)<1024:
        buffer+=byte
    os.write(wr,buffer+'\n')
