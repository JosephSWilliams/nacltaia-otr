#!/usr/bin/env python
import sys, os ; sys.path.append(os.getcwd())
from random import randrange as rR
import binascii
import nacltaia
import base91a
import array
import pwd
import re

uid = pwd.getpwnam('nacltaia-otr')[2]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setuid(uid)
del uid

RE = 'a-zA-Z0-9^(\)-_{\}[\]|'

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

  if re.search('^((PRIVMSG)|(NOTICE)|(TOPIC)) ['+RE+']+ :.*$',buffer.upper()):

    dst = buffer.split(' ',2)[1].lower()

    if dst in os.listdir('dstkey/'):

      m      = buffer.split(':',1)[1]
      m     += '\n' + array.array('B',[rR(0,256) for i in range(0,64-len(m)%64-1)]).tostring()
      n      = nacltaia.taia_now()
      n     += array.array('B',[rR(0,256) for i in range(0,8)]).tostring()
      pk     = open('tmpkey/'+dst+'/tk','rb').read(32)
      sk     = open('tmpkey/'+dst+'/sk','rb').read(32)
      c      = nacltaia.crypto_box(m,n,pk,sk)
      c      = str() if c == 0 else c
      c      = open('tmpkey/'+dst+'/pk','rb').read(32) + c
      pk     = binascii.unhexlify(open('dstkey/'+dst,'rb').read(64))
      sk     = binascii.unhexlify(open('seckey','rb').read(64))
      c      = nacltaia.crypto_box(c,n,pk,sk)
      buffer = buffer.split(':',1)[0] + ':' + base91a.encode(n+c)

  elif re.search('^((PRIVMSG)|(NOTICE)|(TOPIC)) #['+RE+']+ :.*$',buffer.upper()):

    dst = buffer.split(' ',2)[1].lower()[1:]

    if dst in os.listdir('chnkey/'):

      m      = buffer.split(':',1)[1]
      m     += '\n' + array.array('B',[rR(0,256) for i in range(0,111-len(m)%111)]).tostring()
      n      = nacltaia.taia_now()
      n     += array.array('B',[rR(0,256) for i in range(0,8)]).tostring()
      k      = binascii.unhexlify(open('chnkey/'+dst,'rb').read(64))
      c      = nacltaia.crypto_secretbox(m,n,k)
      c      = str() if c == 0 else c
      buffer = buffer.split(':',1)[0] + ':' + base91a.encode(n+c)

  os.write(1,buffer+'\n')
