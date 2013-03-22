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

RE = 'a-zA-Z0-9^(\)\-_{\}[\]|'
re_SPLIT_SPACE = re.compile(' +',re.IGNORECASE).split
re_SPLIT_SPACE_COLON = re.compile(' +:?',re.IGNORECASE).split
re_SPLIT_BRACKETS = re.compile('\[|]',re.IGNORECASE).split
re_CRYPTOSERV = re.compile('^:['+RE+']+!nacltaia-otr@service',re.IGNORECASE).search
re_NICK_PRIVMSG_NOTICE_TOPIC = re.compile('^:['+RE+']+![~'+RE+'.]+@['+RE+'.]+ +((PRIVMSG)|(NOTICE)|(TOPIC)) +['+RE+']+ +:?.*$',re.IGNORECASE).search
re_CHANNEL_PRIVMSG_NOTICE_TOPIC = re.compile('^:['+RE+']+![~'+RE+'.]+@['+RE+'.]+ +((PRIVMSG)|(NOTICE)|(TOPIC)) +#['+RE+']+ +:?.*$',re.IGNORECASE).search
re_322_332 = re.compile('^:['+RE+'.]+ +((322)|(332)) +['+RE+']+ +#['+RE+']+ ?([0-9]+)? +:?.*$',re.IGNORECASE).search
re_BUFFER_CTCP_DCC = re.compile('\x01(?!ACTION )',re.IGNORECASE).sub
re_BUFFER_COLOUR = re.compile('(\x03[0-9][0-9]?((?<=[0-9]),[0-9]?[0-9]?)?)|[\x02\x03\x0f\x1d\x1f]',re.IGNORECASE).sub

uid, gid = pwd.getpwnam('nacltaia-otr')[2:4]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setgid(gid)
os.setuid(uid)
del uid, gid

ipc=socket.socket(1,1) # contains potential race condition
for n in range(0,9):
  if n == 8: sys.exit(128+111)
  try:
    ipc.connect('socket')
    del n
    break
  except:
    time.sleep(0.1)
ipc_POLLIN=select.poll()
ipc_POLLIN.register(ipc.fileno(),3)
def ipc_poll():
  return len(ipc_POLLIN.poll(0))

COLOUR = int(open('COLOUR','rb').read().split('\n')[0]) if os.path.exists('COLOUR') else 0
UNICODE = int(open('UNICODE','rb').read().split('\n')[0]) if os.path.exists('UNICODE') else 0

HASH_LOG = int(open('HASH_LOG','rb').read().split('\n')[0]) if os.path.exists('HASH_LOG') else 256
OK_SECONDS = int(open('OK_SECONDS','rb').read().split('\n')[0]) if os.path.exists('OK_SECONDS') else 128

taias = dict()
hashcache = collections.deque([],HASH_LOG)

def oksrctaia(n,taia,taia_now):
  if nacltaia.taia_okseconds(n,taia)<1: return 0
  if nacltaia.taia_new(taia,taias[src])<1:
    return 1 if taia_now == taias[src] else 0
  return 1

def cached(h):
  if h in hashcache: return 1
  hashcache.append(h)
  return 0

while 1:

  buffer = str()
  while 1:
    byte = os.read(0,1)
    if byte == '': sys.exit(0)
    if byte == '\n': break
    if byte != '\r' and len(buffer)<1024: buffer += byte

  while ipc_poll():
    h = ipc.recv(32)
    if len(h) < 32: sys.exit(128+32)
    cached(h)

  if re_CRYPTOSERV(buffer): continue

  taia_now = nacltaia.taia_now_pack()

  if re_NICK_PRIVMSG_NOTICE_TOPIC(buffer):

    src = buffer[1:].split('!',1)[0].lower()

    if src in os.listdir('dstkey/'):

      c = base91a.decode(re_SPLIT_SPACE_COLON(buffer,3)[3])

      if not c: continue

      n  = c[:24]
      c  = c[24:]
      pk = base91a.hex2bin(open('dstkey/'+src,'rb').read(64))
      sk = base91a.hex2bin(open('seckey','rb').read(64))
      c  = nacltaia.crypto_box_open(c,n,pk,sk)

      if c == 0: continue

      m    = 0
      taia = n[:16]

      if len(c) >= 32 + 16:
        pk = c[:32]
        sk = open('tmpkey/'+src+'/sk','rb').read(32)
        m  = nacltaia.crypto_box_open(c[32:],n,pk,sk)

      else: continue

      if not src in taias.keys(): taias[src] = taia_now

      if not oksrctaia(OK_SECONDS,taia,taia_now): continue

      if open('tmpkey/'+src+'/tk','rb').read(32) != pk: open('tmpkey/'+src+'/tk','wb').write(pk)

      taias[src] = taia

      if m == 0:
        os.write(1,':' + buffer[1:].split('!',1)[0] + '!nacltaia-otr@service NOTICE ' + re_SPLIT_SPACE(buffer,3)[2] + ' :unable to decrypt message\a\n')
        continue

      else: buffer = ' '.join(re_SPLIT_SPACE(buffer,3)[:3]) + ' :' + m.split('\n',1)[0]

  elif re_CHANNEL_PRIVMSG_NOTICE_TOPIC(buffer):

    src = buffer[1:].split('!',1)[0].lower()
    dst = re_SPLIT_SPACE(buffer,3)[2].lower()[1:]
    m   = re_SPLIT_SPACE_COLON(buffer,3)[3]
    h   = nacltaia.crypto_hash_sha256(m)

    if dst in os.listdir('chnkey/'):

      c = base91a.decode(m)

      if not c: continue

      n = c[:24]
      c = c[24:]
      k = base91a.hex2bin(open('chnkey/'+dst,'rb').read(64))
      m = nacltaia.crypto_secretbox_open(c,n,k)

      if m == 0: continue

      taia = n[:16]

      if taia == '\x00'*16 and len(c) >= 32 + 64 + 24:

        pk = m[:32]
        m  = nacltaia.crypto_sign_open(m[32:],pk)

        if m == 0: continue

        if n != m[:24]: continue

        m    = m[24:]
        taia = n[16:] + '\x00'*8

        if dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):

          if pk != base91a.hex2bin(open('unsign/'+dst+'/'+src,'rb').read(64)): continue

          if not src in taias.keys(): taias[src] = taia_now

          if not oksrctaia(OK_SECONDS,taia,taia_now): continue

          taias[src] = taia

        elif nacltaia.taia_okseconds(OK_SECONDS,taia)<1: continue

        elif cached(h): continue

      elif dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'): continue

      elif nacltaia.taia_okseconds(OK_SECONDS,taia)<1: continue

      elif cached(h): continue

      buffer = ' '.join(re_SPLIT_SPACE(buffer,3)[:3]) + ' :' + m.split('\n',1)[0]

    elif dst in os.listdir('unsign/') and src in os.listdir('unsign/'+dst+'/'):

      m  = base91a.decode(m)
      pk = m[24:56]
      n  = m[:24]
      m  = nacltaia.crypto_sign_open(m[56:],pk)

      if m == 0: continue

      if n != m[:24]: continue

      m = m[24:]

      taia = n[:16]

      if pk != base91a.hex2bin(open('unsign/'+dst+'/'+src,'rb').read(64)): continue

      if not src in taias.keys(): taias[src] = taia_now

      if not oksrctaia(OK_SECONDS,taia,taia_now): continue

      taias[src] = taia

      buffer = ' '.join(re_SPLIT_SPACE(buffer,3)[:3]) + ' :' + m.split('\n',1)[0]

    elif len(m) >= 56 + 64 and not ' ' in m:

      m = re_SPLIT_SPACE_COLON(buffer,3)[3]
      h = nacltaia.crypto_hash_sha256(m)
      m = base91a.decode(re_SPLIT_SPACE_COLON(buffer,3)[3])

      if m[16:24] == '\x00'*8:

        n  = m[:24]
        pk = m[24:56]

        m = nacltaia.crypto_sign_open(m[56:],pk)

        if m == 0: continue

        if n != m[:24]: continue

        m = m[24:]

        taia = n[:16]

        if nacltaia.taia_okseconds(OK_SECONDS,taia)<1: continue

        elif cached(h): continue

      else: m = re_SPLIT_SPACE_COLON(buffer,3)[3]

      buffer = ' '.join(re_SPLIT_SPACE(buffer,3)[:3]) + ' :' + m.split('\n',1)[0]

  elif re_322_332(buffer):

    dst = re_SPLIT_SPACE(buffer,4)[3].lower()[1:]
    cmd = re_SPLIT_SPACE(buffer,2)[1]
    m   = re_SPLIT_BRACKETS(re_SPLIT_SPACE_COLON(buffer,5)[5],2)[2][1:] if cmd == '322' else re_SPLIT_SPACE_COLON(buffer,4)[4]

    if dst in os.listdir('chnkey/'):

      c = base91a.decode(m)

      c = str() if c == 0 else c

      n = c[:24]
      c = c[24:]
      k = base91a.hex2bin(open('chnkey/'+dst,'rb').read(64))
      m = nacltaia.crypto_secretbox_open(c,n,k)

      m = str() if m == 0 else m

      taia = n[:16]

      if len(n) >= 16 and taia == '\x00'*16:
        pk = m[:32]
        m  = nacltaia.crypto_sign_open(m[32:],pk)
        m  = str() if m == 0 else m
        m  = m[24:]

    elif len(m) >= 56 + 64 and not ' ' in m:

      m = base91a.decode(m)

      if m[16:24] == '\x00'*8:
        pk = m[24:56]
        n  = m[:24]
        m  = nacltaia.crypto_sign_open(m[56:],pk)
        m  = str() if m == 0 else m
        m  = m[24:]

      else: m = re_SPLIT_BRACKETS(re_SPLIT_SPACE_COLON(buffer,5)[5],2)[2][1:] if cmd == '322' else re_SPLIT_SPACE_COLON(buffer,4)[4]

    else: m = re_SPLIT_BRACKETS(re_SPLIT_SPACE_COLON(buffer,5)[5],2)[2][1:] if cmd == '322' else re_SPLIT_SPACE_COLON(buffer,4)[4]

    if cmd == '322':

      m = '[' + re_SPLIT_BRACKETS(re_SPLIT_SPACE_COLON(buffer,5)[5],2)[1] + '] ' + m

      buffer = ' '.join(re_SPLIT_SPACE(buffer,5)[:5]) + ' :' + m.split('\n',1)[0]

    elif cmd == '332': buffer = ' '.join(re_SPLIT_SPACE(buffer,4)[:4]) + ' :' + m.split('\n',1)[0]

  buffer = re_BUFFER_CTCP_DCC('',buffer)
  if not COLOUR: buffer = re_BUFFER_COLOUR('',buffer)
  if not UNICODE:
    buffer = codecs.ascii_encode(unicodedata.normalize('NFKD',unicode(buffer,'utf-8','replace')),'ignore')[0]
    buffer = ''.join(byte for byte in buffer if 127 > ord(byte) > 31 or byte in ['\x01','\x02','\x03','\x0f','\x1d','\x1f'])
  buffer += '\n'

  os.write(1,buffer)
