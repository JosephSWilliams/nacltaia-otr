#!/usr/bin/env python
import sys, os ; sys.path.append(os.getcwd())
import unicodedata
import collections
import nacltaia
import base91a
import codecs
import select
import socket
import time
import pwd
import re

uid = pwd.getpwnam('nacltaia-otr')[2]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setuid(uid)
del uid

ipc=socket.socket(1,1) # contains potential race condition
for n in range(0,8):
  sys.exit(128+111) if n == 8 else 0
  try:
    ipc.connect('socket')
    del n
    break
  except:
    time.sleep(1)
ipc_POLLIN=select.poll()
ipc_POLLIN.register(ipc.fileno(),3)
def ipc_poll():
  return len(ipc_POLLIN.poll(0))

OK_SECONDS = 64
HASH_LOG   = 128
taias      = dict()
RE         = 'a-zA-Z0-9^(\)\-_{\}[\]|'
hashcache  = collections.deque([],HASH_LOG)

def oktaia(n,taia):
  return 1 if abs( nacltaia.taia2seconds(nacltaia.taia_now()) - nacltaia.taia2seconds(taia) ) < n else 0

def oksrctaia(n,taia,taia_now):
  if abs( nacltaia.taia2seconds(nacltaia.taia_now()) - nacltaia.taia2seconds(taia) ) > n:
    return 0
  if nacltaia.taia_new(taia,taias[src])<1:
    return 1 if taia_now == taias[src] else 0
  return 1

def cached(h):
  if h in hashcache:
    return 1
  hashcache.append(h)
  return 0

while 1:

  buffer = str()

  while 1:
    byte = os.read(0,1)
    if not byte:
      sys.exit(0)
    if byte == '\n':
      break
    if byte != '\r' and len(buffer)<1024:
      buffer+=byte

  while ipc_poll():
    h = ipc.recv(32)
    if len(h) < 32:
      sys.exit(128+32)
    cached(h)

  if re.search('^:cryptoserv',buffer.lower()):
    continue

  taia_now = nacltaia.taia_now()

  if re.search('^:['+RE+']+![~'+RE+'.]+@['+RE+'.]+ +((PRIVMSG)|(NOTICE)|(TOPIC)) +['+RE+']+ +:?.*$',buffer.upper()):

    src = buffer[1:].split('!',1)[0].lower()

    if src in os.listdir('dstkey/'):

      c = base91a.decode(re.split(' +:?',buffer,3)[3])

      if not c:
        continue

      n  = c[:24]
      c  = c[24:]
      pk = base91a.hex2bin(open('dstkey/'+src,'rb').read(64))
      sk = base91a.hex2bin(open('seckey','rb').read(64))
      c  = nacltaia.crypto_box_open(c,n,pk,sk)

      if c == 0:
        continue

      m    = 0
      taia = n[:16]

      if len(c) >= 32 + 16:
        pk = c[:32]
        sk = open('tmpkey/'+src+'/sk','rb').read(32)
        m  = nacltaia.crypto_box_open(c[32:],n,pk,sk)

      else:
        continue

      if not src in taias.keys():
        taias[src] = taia_now

      if not oksrctaia(OK_SECONDS,taia,taia_now):
        continue

      if open('tmpkey/'+src+'/tk','rb').read(32) != pk:
        open('tmpkey/'+src+'/tk','wb').write(pk)

      taias[src] = taia

      if m == 0:
        os.write(1,':CryptoServ!nacltaia-otr@service NOTICE ' + re.split(' +',buffer,3)[2] + ' :unable to decrypt message from ' + src + '\a\n')
        continue

      else:
        buffer = re.split(' +',buffer,1)[0] \
               + ' ' \
               + re.split(' +',buffer,2)[1].upper() \
               + ' ' \
               + re.split(' +',buffer,3)[2] \
               + ' :' \
               + m.split('\n',1)[0]

  elif re.search('^:['+RE+']+![~'+RE+'.]+@['+RE+'.]+ +((PRIVMSG)|(NOTICE)|(TOPIC)) +#['+RE+']+ +:?.*$',buffer.upper()):

    src = buffer[1:].split('!',1)[0].lower()
    dst = re.split(' +',buffer,3)[2].lower()[1:]
    m   = re.split(' +:?',buffer,3)[3]
    h   = nacltaia.crypto_hash_sha256(m)

    if dst in os.listdir('chnkey/'):

      c = base91a.decode(m)

      if not c:
        continue

      n = c[:24]
      c = c[24:]
      k = base91a.hex2bin(open('chnkey/'+dst,'rb').read(64))
      m = nacltaia.crypto_secretbox_open(c,n,k)

      if m == 0:
        continue

      taia = n[:16]

      if not nacltaia.taia2seconds(taia) and len(c) >= 32 + 64 + 24:

        pk = m[:32]
        m  = nacltaia.crypto_sign_open(m[32:],pk)

        if m == 0:
          continue

        if n != m[:24]:
          continue

        m    = m[24:]
        taia = n[16:] + '\x00\x00\x00\x00\x00\x00\x00\x00'

        if dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):

          if pk != base91a.hex2bin(open('unsign/'+dst+'/'+src,'rb').read(64)):
            continue

          if not src in taias.keys():
            taias[src] = taia_now

          if not oksrctaia(OK_SECONDS,taia,taia_now):
            continue

          taias[src] = taia

        elif not oktaia(OK_SECONDS,taia):
          continue

        elif cached(h):
          continue

      elif dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):
        continue

      elif not oktaia(OK_SECONDS,taia):
        continue

      elif cached(h):
        continue

      buffer = re.split(' +',buffer,1)[0] \
             + ' ' \
             + re.split(' +',buffer,2)[1].upper() \
             + ' ' \
             + re.split(' +',buffer,3)[2] \
             + ' :' \
             + m.split('\n',1)[0]

    elif dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):

      m  = base91a.decode(m)
      pk = m[24:56]
      n  = m[:24]
      m  = nacltaia.crypto_sign_open(m[56:],pk)

      if m == 0:
        continue

      if n != m[:24]:
        continue

      m = m[24:]

      taia = n[:16]

      if pk != base91a.hex2bin(open('unsign/'+dst+'/'+src,'rb').read(64)):
        continue

      if not src in taias.keys():
        taias[src] = taia_now

      if not oksrctaia(OK_SECONDS,taia,taia_now):
        continue

      taias[src] = taia

      buffer = re.split(' +',buffer,1)[0] \
             + ' ' \
             + re.split(' +',buffer,2)[1].upper() \
             + ' ' \
             + re.split(' +',buffer,3)[2] \
             + ' :' \
             + m.split('\n',1)[0]

    elif len(m) >= 56 + 64 and not ' ' in m:

      m = re.split(' +:?',buffer,3)[3]
      h = nacltaia.crypto_hash_sha256(m)
      m = base91a.decode(re.split(' +:?',buffer,3)[3])

      if m[16:24] == '\x00\x00\x00\x00\x00\x00\x00\x00':

        n  = m[:24]
        pk = m[24:56]

        m = nacltaia.crypto_sign_open(m[56:],pk)

        if m == 0:
          continue

        if n != m[:24]:
          continue

        m = m[24:]

        taia = n[:16]

        if not oktaia(OK_SECONDS,taia):
          continue

        elif cached(h):
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

  elif re.search('^:['+RE+'.]+ +((322)|(332)) +['+RE+']+ +#['+RE+']+ ?([0-9]+)? +:?.*$',buffer.upper()):

    dst = re.split(' +',buffer,4)[3].lower()[1:]
    cmd = re.split(' +',buffer,2)[1]
    m   = re.split('\[|]',buffer,2)[2][1:] if cmd == '322' else re.split(' +:?',buffer,4)[4]

    if dst in os.listdir('chnkey/'):

      c = base91a.decode(m)

      c = str() if c == 0 else c

      n = c[:24]
      c = c[24:]
      k = base91a.hex2bin(open('chnkey/'+dst,'rb').read(64))
      m = nacltaia.crypto_secretbox_open(c,n,k)

      m = str() if m == 0 else m

      taia = n[:16]

      if len(n) >= 16 and not nacltaia.taia2seconds(taia):
        pk = m[:32]
        m  = nacltaia.crypto_sign_open(m[32:],pk)
        m  = str() if m == 0 else m
        m  = m[24:]

    elif len(m) >= 56 + 64 and not ' ' in m:

      m = base91a.decode(m)

      if m[16:24] == '\x00\x00\x00\x00\x00\x00\x00\x00':
        pk = m[24:56]
        n  = m[:24]
        m  = nacltaia.crypto_sign_open(m[56:],pk)
        m  = str() if m == 0 else m
        m  = m[24:]

      else:
        m = re.split('\[|]',buffer,2)[2][1:] if cmd == '322' else re.split(' +:?',buffer,4)[4]

    else:
      m = re.split('\[|]',buffer,2)[2][1:] if cmd == '322' else re.split(' +:?',buffer,4)[4]

    if cmd == '322':

      m = '[' + re.split('\[|]',buffer,2)[1] + '] ' + m

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

    elif cmd == '332':

      buffer = re.split(' +',buffer,1)[0] \
             + ' ' \
             + re.split(' +',buffer,2)[1] \
             + ' ' \
             + re.split(' +',buffer,3)[2] \
             + ' ' \
             + re.split(' +',buffer,4)[3] \
             + ' :' \
             + m.split('\n',1)[0]

  buffer = codecs.ascii_encode(unicodedata.normalize('NFKD',unicode(buffer,'utf-8','replace')),'ignore')[0]
  buffer = re.sub('[\x02\x0f]','',buffer)
  buffer = re.sub('\x01(ACTION )?','*',buffer) # contains potential irssi bias
  buffer = re.sub('\x03[0-9]?[0-9]?((?<=[0-9]),[0-9]?[0-9]?)?','',buffer)
  buffer = str({str():buffer})[6:][:len(str({str():buffer})[6:])-2] + '\n'
  buffer = buffer.replace("\\'","'")
  buffer = buffer.replace('\\\\','\\')

  os.write(1,buffer)
