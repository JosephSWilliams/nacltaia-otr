#!/usr/bin/env python
import sys, os ; sys.path.append(os.getcwd())
import binascii
import nacltaia
import base91a
import re

taias    = dict()
taia_now = binascii.hexlify(nacltaia.taia_now())
sk       = binascii.unhexlify(open('crypto/seckey','rb').read(64))

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

  if re.search('^:\w+!\w+@[\w.]+ ((PRIVMSG)|(NOTICE)|(TOPIC)) #?\w+ :.*$',buffer.upper()):

    src = buffer.split(':',2)[1].split('!',1)[0]

    if src in os.listdir(os.getcwd()):
      try:

        c = base91a.decode(buffer.split(':',2)[2])[24:]
        n = base91a.decode(buffer.split(':',2)[2])[:24]

        if len(n) + len(c) < 24 + 16:
          continue

        pk = binascii.unhexlify(open(src,'rb').read(64))
        m  = nacltaia.crypto_box_open(c,n,pk,sk).split('\n',1)[0]

        if m == 0:
          continue

        taia = binascii.hexlify(n[:16])

        if not src in taias.keys():
          taias[src] = taia_now
          taia_now   = binascii.hexlify(nacltaia.taia_now())

        if long(taia,16) < long(taias[src],16):
          continue

        taias[src] = taia
        buffer     = ':' + buffer.split(':',2)[1] + ':' + m

      except:
        continue

  os.write(1,buffer+'\n')
