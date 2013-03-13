#!/usr/bin/env python
from random import randrange as rR
from subprocess import *
from array import array
from time import sleep
from sys import *
import pwd
import os

if len(argv)>1:
  uid, gid = pwd.getpwnam('nacltaia-otr')[2:4]
  p=Popen(['./crypto_box_keypair'],stdin=-1,stdout=-1) # cannot chroot and read /dev/urandom
  os.chdir(argv[1])
  os.chroot(os.getcwd())
  os.setgid(gid)
  os.setuid(uid)
  del uid, gid
  for dst in os.listdir('dstkey/'):
    if not os.path.exists('tmpkey/'+dst): os.mkdir('tmpkey/'+dst)
    open('tmpkey/'+dst+'/tk','ab').write(str())
    for n in range(0,32):
      rk = array('B',[rR(0,256) for i in range(0,32)]).tostring()
      open('tmpkey/'+dst+'/pk','wb').write(rk)
      open('tmpkey/'+dst+'/sk','wb').write(rk)
      p.stdin.write('\n')
    pk, sk = p.stdout.read(32), p.stdout.read(32)
    open('tmpkey/'+dst+'/pk','wb').write(pk)
    open('tmpkey/'+dst+'/sk','wb').write(sk)
  p.stdin.write(str())
  sleep(int(argv[2])) if len(argv)>2 else sleep(1)
else:
  exit(argv[0]+': </path/to/crypto> <iteration>')
