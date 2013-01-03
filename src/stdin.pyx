#!/usr/bin/env python
import sys, os ; sys.path.append(os.getcwd())
from random import randrange as rR
import binascii
import nacltaia
import base91a
import array
import re

sk = binascii.unhexlify(open('crypto/seckey','rb').read(64))

os.chdir('crypto/dstkey/')
os.chroot(os.getcwd())

while 1:

  buffer = str()

  while 1:
    byte = os.read(0,1)
    if not byte or len(buffer)>1024:
      sys.exit(0)
    if byte == '\n':
      break
    if byte != '\r':
      buffer+=byte

  if re.search('^((PRIVMSG)|(NOTICE)|(TOPIC)) #?\w+ :.*$',buffer.upper()):

    dst = buffer.split(' ',2)[1].lower()

    if dst in os.listdir(os.getcwd()):

      m      = buffer.split(':',1)[1]
      m     += '\n' + array.array('B',[rR(0,256) for i in range(0,112-len(m)%112-1)]).tostring()
      n      = nacltaia.taia_now()
      n     += array.array('B',[rR(0,256) for i in range(0,8)]).tostring()
      pk     = binascii.unhexlify(open(dst,'rb').read(64))
      c      = nacltaia.crypto_box(m,n,pk,sk)
      buffer = buffer.split(':',1)[0] + ':' + base91a.encode(n+c)

  os.write(1,buffer+'\n')
