#!/usr/bin/env python
import sys, os ; sys.path.append(os.getcwd())
from random import randrange as rR
import nacltaia
import base91a
import socket
import array
import time
import pwd
import re

uid, gid = pwd.getpwnam('nacltaia-otr')[2:4]
os.chdir('crypto/')
os.chroot(os.getcwd())
os.setgid(gid)
os.setuid(uid)
del uid, gid

sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) # contains potential race condition
sock.bind('socket')
sock.listen(1)
ipc=sock.accept()[0]
os.remove('socket')
sock.close()
del sock

RE = 'a-zA-Z0-9^(\)\-_{\}[\]|'
re_SPLIT_SPACE = re.compile(' +',re.IGNORECASE).split
re_SPLIT_SPACE_COLON = re.compile(' +:?',re.IGNORECASE).split
re_PRIVMSG_NICK = re.compile('^((PRIVMSG)|(NOTICE)|(TOPIC)) +['+RE+']+ +:?.*$',re.IGNORECASE).search
re_PRIVMSG_CHANNEL = re.compile('^((PRIVMSG)|(NOTICE)|(TOPIC)) +#['+RE+']+ +:?.*$',re.IGNORECASE).search

while 1:

  buffer = str()
  while 1:
    byte = os.read(0,1)
    if byte == '': sys.exit(0)
    if byte == '\n': break
    if byte != '\r' and len(buffer)<1024: buffer += byte

  if re_PRIVMSG_NICK(buffer):

    dst = re_SPLIT_SPACE_COLON(buffer,2)[1].lower()

    if dst in os.listdir('dstkey/'):

      m      = re.split(' +:?',buffer,2)[2]
      m     += '\n' + array.array('B',[rR(0,256) for i in range(0,256-(len(m)+1+24+32+16+16)%256)]).tostring()
      n      = nacltaia.taia_now_pack()
      n     += array.array('B',[rR(0,256) for i in range(0,8)]).tostring()
      pk     = open('tmpkey/'+dst+'/tk','rb').read(32)
      sk     = open('tmpkey/'+dst+'/sk','rb').read(32)
      c      = nacltaia.crypto_box(m,n,pk,sk)
      c      = str() if c == 0 else c
      c      = open('tmpkey/'+dst+'/pk','rb').read(32) + c
      pk     = base91a.hex2bin(open('dstkey/'+dst,'rb').read(64))
      sk     = base91a.hex2bin(open('seckey','rb').read(64))
      c      = nacltaia.crypto_box(c,n,pk,sk)
      c      = str() if c == 0 else c
      buffer = ' '.join(re_SPLIT_SPACE(buffer,2)[:2]) + ' :' + base91a.encode(n+c)

  elif re_PRIVMSG_CHANNEL(buffer):

    dst = re_SPLIT_SPACE_COLON(buffer,2)[1].lower()[1:]
    h   = str()

    if dst in os.listdir('sign/') and dst in os.listdir('chnkey/'):

      time.sleep(1) # ensure 1 second increment

      m      = re_SPLIT_SPACE_COLON(buffer,2)[2]
      m     += '\n' + array.array('B',[rR(0,256) for i in range(0,256-(len(m)+1+24+24+32+64+16)%256)]).tostring()
      pk     = base91a.hex2bin(open('sign/'+dst+'/pubkey','rb').read(64))
      sk     = base91a.hex2bin(open('sign/'+dst+'/seckey','rb').read(128))
      n      = array.array('B',[0 for i in range(0,16)]).tostring()
      n     += nacltaia.taia_now_pack()[:8]
      m      = nacltaia.crypto_sign(n+m,sk)
      m      = str() if m == 0 else m
      m      = pk + m
      k      = base91a.hex2bin(open('chnkey/'+dst,'rb').read(64))
      c      = nacltaia.crypto_secretbox(m,n,k)
      c      = str() if c == 0 else c
      c      = base91a.encode(n+c)
      h      = nacltaia.crypto_hash_sha256(c)
      buffer = ' '.join(re_SPLIT_SPACE(buffer,2)[:2]) + ' :' + c

    elif dst in os.listdir('chnkey/'):

      m      = re_SPLIT_SPACE_COLON(buffer,2)[2]
      m     += '\n' + array.array('B',[rR(0,256) for i in range(0,256-(len(m)+1+24+16)%256)]).tostring()
      n      = nacltaia.taia_now_pack()
      n     += array.array('B',[rR(0,256) for i in range(0,8)]).tostring()
      k      = base91a.hex2bin(open('chnkey/'+dst,'rb').read(64))
      c      = nacltaia.crypto_secretbox(m,n,k)
      c      = str() if c == 0 else c
      c      = base91a.encode(n+c)
      h      = nacltaia.crypto_hash_sha256(c)
      buffer = ' '.join(re_SPLIT_SPACE(buffer,2)[:2]) + ' :' + c

    elif dst in os.listdir('sign/'):

      m      = re_SPLIT_SPACE_COLON(buffer,2)[2]
      m     += '\n'
      n      = nacltaia.taia_now_pack()
      n     += array.array('B',[0 for i in range(0,8)]).tostring()
      pk     = base91a.hex2bin(open('sign/'+dst+'/pubkey','rb').read(64))
      sk     = base91a.hex2bin(open('sign/'+dst+'/seckey','rb').read(128))
      m      = nacltaia.crypto_sign(n+m,sk)
      m      = str() if m == 0 else m
      m      = base91a.encode(n+pk+m)
      h      = nacltaia.crypto_hash_sha256(m)
      buffer = ' '.join(re_SPLIT_SPACE(buffer,2)[:2]) + ' :' + m

    try:
      if h and buffer[:6].upper() != 'TOPIC ': ipc.send(h)
    except:
      sys.exit(128+32)

  os.write(1,buffer+'\n')
