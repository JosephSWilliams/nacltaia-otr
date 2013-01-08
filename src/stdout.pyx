#!/usr/bin/env python
import sys, os ; sys.path.append(os.getcwd())
import unicodedata
import binascii
import nacltaia
import base91a
import codecs
import pwd
import re

uid = pwd.getpwnam('nacltaia-otr')[2]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setuid(uid)
del uid

taias    = dict()
RE       = 'a-zA-Z0-9^(\)-_{\}[\]|'
taia_now = binascii.hexlify(nacltaia.taia_now())

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

  if re.search('^:['+RE+']+!['+RE+']+@['+RE+'.]+ ((PRIVMSG)|(NOTICE)|(TOPIC)) ['+RE+']+ :.*$',buffer.upper()):

    src = buffer.split(':',2)[1].split('!',1)[0].lower()

    if src in os.listdir('dstkey/'):
      try:

        c = base91a.decode(buffer.split(':',2)[2])

        if len(c) < 24 + 16:
          continue

        n = c[:24]
        c = c[24:]

        pk = binascii.unhexlify(open('dstkey/'+src,'rb').read(64))
        sk = binascii.unhexlify(open('seckey','rb').read(64))
        m  = nacltaia.crypto_box_open(c,n,pk,sk).split('\n',1)[0]

        if m == 0:
          continue

        taia = binascii.hexlify(n[:16])

        if not src in taias.keys():
          taias[src] = taia_now
          taia_now   = binascii.hexlify(nacltaia.taia_now())

        if long(taia,16) <= long(taias[src],16):
          continue

        taias[src] = taia
        buffer     = ':' + buffer.split(':',2)[1] + ':' + m

      except:
        continue

  elif re.search('^:['+RE+']+!['+RE+']+@['+RE+'.]+ ((PRIVMSG)|(NOTICE)|(TOPIC)) #['+RE+']+ :.*$',buffer.upper()):

    src = buffer.split(':',2)[1].split('!',1)[0].lower()
    dst = buffer.split(' ',3)[2].lower()[1:]

    if dst in os.listdir('chnkey/'):

      if not src in os.listdir('dstkey/'):
        continue

      try:

        c = base91a.decode(buffer.split(':',2)[2])

        if len(c) < 24 + 16:
          continue

        n = c[:24]
        c = c[24:]

        k = binascii.unhexlify(open('chnkey/'+dst,'rb').read(64))
        m = nacltaia.crypto_secretbox_open(c,n,k).split('\n',1)[0]

        if m == 0:
          continue

        taia = binascii.hexlify(n[:16])

        if not src in taias.keys():
          taias[src] = taia_now
          taia_now   = binascii.hexlify(nacltaia.taia_now())

        if long(taia,16) <= long(taias[src],16):
          continue

        taias[src] = taia
        buffer     = ':' + buffer.split(':',2)[1] + ':' + m

      except:
        continue

  buffer = codecs.ascii_encode(unicodedata.normalize('NFKD',unicode(buffer,'utf-8','replace')),'ignore')[0]
  buffer = re.sub('[\x02\x0f]','',buffer)
  buffer = re.sub('\x01(ACTION )?','*',buffer) # contains potential irssi bias
  buffer = re.sub('\x03[0-9][0-9]?(,[0-9][0-9]?)?','',buffer)
  buffer = str({str():buffer})[6:][:len(str({str():buffer})[6:])-2] + '\n'
  buffer = buffer.replace("\\'","'")
  buffer = buffer.replace('\\\\','\\')

  if len(buffer)<=1024:
    os.write(1,buffer)
