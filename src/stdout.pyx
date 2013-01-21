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

taias = dict()
RE    = 'a-zA-Z0-9^(\)\-_{\}[\]|'

def oktaia(n,taia):
  taia     = taia[:16]
  taia_now = binascii.hexlify(nacltaia.taia_now()[:8])
  return 1 if abs( long(taia_now,16) - long(taia,16) ) < n else 0

def oksrctaia(taia,taia_now):
  if long(taia,16) <= long(taias[src],16):
    return 1 if taia_now == taias[src] else 0
  return 1

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

  if re.search('^:cryptoserv',buffer.lower()):
    continue

  taia_now = binascii.hexlify(nacltaia.taia_now())

  if re.search('^:['+RE+']+!['+RE+']+@['+RE+'.]+ +((PRIVMSG)|(NOTICE)|(TOPIC)) +['+RE+']+ +:?.*$',buffer.upper()):

    src = buffer[1:].split('!',1)[0].lower()

    if src in os.listdir('dstkey/'):

      c = base91a.decode(re.split(' +:?',buffer,3)[3])

      if not c:
        continue

      n  = c[:24]
      c  = c[24:]
      pk = binascii.unhexlify(open('dstkey/'+src,'rb').read(64))
      sk = binascii.unhexlify(open('seckey','rb').read(64))
      c  = nacltaia.crypto_box_open(c,n,pk,sk)

      if c == 0:
        continue

      m    = 0
      taia = binascii.hexlify(n[:16])

      if len(c) >= 32 + 16:
        pk = c[:32]
        sk = open('tmpkey/'+src+'/sk','rb').read(32)
        m  = nacltaia.crypto_box_open(c[32:],n,pk,sk)

      else:
        continue

      if not src in taias.keys():
        taias[src] = taia_now

      if not oksrctaia(taia,taia_now):
        continue

      if open('tmpkey/'+src+'/tk','rb').read(32) != pk:
        open('tmpkey/'+src+'/tk','wb').write(pk)

      taias[src] = taia

      if m == 0:
        buffer = ':CryptoServ!nacltaia-otr@service NOTICE ' + re.split(' +',buffer,3)[2] + ' :unable to decrypt message from ' + src + '\a\n'
        os.write(1,buffer)
        continue

      else:
        buffer = re.split(' +',buffer,1)[0] \
               + ' ' \
               + re.split(' +',buffer,2)[1].upper() \
               + ' ' \
               + re.split(' +',buffer,3)[2] \
               + ' :' \
               + m.split('\n',1)[0]

  elif re.search('^:['+RE+']+!['+RE+']+@['+RE+'.]+ +((PRIVMSG)|(NOTICE)|(TOPIC)) +#['+RE+']+ +:?.*$',buffer.upper()):

    src = buffer[1:].split('!',1)[0].lower()
    dst = re.split(' +',buffer,3)[2].lower()[1:]
    m   = re.split(' +:?',buffer,3)[3]

    if dst in os.listdir('chnkey/'):

      c = base91a.decode(m)

      if not c:
        continue

      n = c[:24]
      c = c[24:]
      k = binascii.unhexlify(open('chnkey/'+dst,'rb').read(64))
      m = nacltaia.crypto_secretbox_open(c,n,k)

      if m == 0:
        continue

      taia = binascii.hexlify(n[:16])

      if not long(taia,16) and len(c) >= 32 + 64 + 24:

        pk = m[:32]
        m  = nacltaia.crypto_sign_open(m[32:],pk)

        if m == 0:
          continue

        if n != m[:24]:
          continue

        m    = m[24:]
        taia = binascii.hexlify(n[16:]) + '0000000000000000'

        if dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):

          if pk != binascii.unhexlify(open('unsign/'+dst+'/'+src,'rb').read(64)):
            continue

          if not src in taias.keys():
            taias[src] = taia_now

          if not oksrctaia(taia,taia_now):
            continue

          taias[src] = taia

        elif not oktaia(32,taia):
          continue

      elif dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):
        continue

      elif not oktaia(32,taia):
        continue

      buffer = re.split(' +',buffer,1)[0] \
             + ' ' \
             + re.split(' +',buffer,2)[1].upper() \
             + ' ' \
             + re.split(' +',buffer,3)[2] \
             + ' :' \
             + m.split('\n',1)[0]

    elif len(m) >= 56 + 64:

      m = base91a.decode(re.split(' +:?',buffer,3)[3])

      if m and m[16:24] == '\x00\x00\x00\x00\x00\x00\x00\x00':

        n  = m[:24]
        pk = m[24:56]

        m = nacltaia.crypto_sign_open(m[56:],pk)

        if m == 0:
          continue

        if n != m[:24]:
          continue

        m = m[24:]

        taia = binascii.hexlify(n[:16])

        if dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):

          if pk != binascii.unhexlify(open('unsign/'+dst+'/'+src,'rb').read(64)):
            continue

          if not src in taias.keys():
            taias[src] = taia_now

          if not oksrctaia(taia,taia_now):
            continue

          taias[src] = taia

        elif not oktaia(32,taia):
          continue

      else:
        m = re.split(' +:?',buffer,3)[3]

      buffer = re.split(' +',buffer,1)[0] \
             + ' ' \
             + re.split(' +',buffer,2)[1].upper() \
             + ' ' \
             + re.split(' +',buffer,3)[2] \
             + ' :' \
             + m.split('\n',1)[0]

  elif re.search('^:['+RE+'.]+ +322 +['+RE+']+ +#['+RE+']+ ([0-9]+)? +:?.*$',buffer.upper()):

    dst = re.split(' +',buffer,4)[3].lower()[1:]

    if dst in os.listdir('chnkey/'):

      c = re.split(' +:?',buffer,4)[4]
      c = re.split('([0-9]+)? +:?',c,2)[len(re.split('([0-9]+)? +:?',c,2))-1]
      c = base91a.decode(c)

      c = str() if c == 0 else c

      n = c[:24]
      c = c[24:]
      k = binascii.unhexlify(open('chnkey/'+dst,'rb').read(64))
      m = nacltaia.crypto_secretbox_open(c,n,k)

      m = str() if m == 0 else m

      taia = binascii.hexlify(n[:16])

      if len(n) >= 16 and not long(taia,16):
        pk = m[:32]
        m  = nacltaia.crypto_sign_open(m[32:],pk)
        m  = str() if m == 0 else m
        m  = m[24:]

      if re.search('^:['+RE+'.]+ +322 +['+RE+']+ +#['+RE+']+ +:?.*$',buffer.upper()):

        buffer = re.split(' +',buffer,1)[0] \
               + ' ' \
               + re.split(' +',buffer,2)[1] \
               + ' ' \
               + re.split(' +',buffer,3)[2] \
               + ' ' \
               + re.split(' +',buffer,4)[3] \
               + ' :' \
               + m.split('\n',1)[0]

      elif re.search('^:['+RE+'.]+ +322 +['+RE+']+ +#['+RE+']+ ([0-9]+) +:?.*$',buffer.upper()):

        buffer = re.split(' +',buffer,1)[0] \
               + ' ' \
               + re.split(' +',buffer,2)[1] \
               + ' ' \
               + re.split(' +',buffer,3)[2] \
               + ' ' \
               + re.split(' +',buffer,4)[3] \
               + ' ' \
               + re.split(' +',buffer,5)[4] \
               + ' :' \
               + m.split('\n',1)[0]

  buffer = codecs.ascii_encode(unicodedata.normalize('NFKD',unicode(buffer,'utf-8','replace')),'ignore')[0]
  buffer = re.sub('[\x02\x0f]','',buffer)
  buffer = re.sub('\x01(ACTION )?','*',buffer) # contains potential irssi bias
  buffer = re.sub('\x03[0-9][0-9]?(,[0-9][0-9]?)?','',buffer)
  buffer = str({str():buffer})[6:][:len(str({str():buffer})[6:])-2] + '\n'
  buffer = buffer.replace("\\'","'")
  buffer = buffer.replace('\\\\','\\')

  if len(buffer)<=1024:
    os.write(1,buffer)
