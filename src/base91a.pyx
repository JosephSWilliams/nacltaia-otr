def encode(binary):
  string, b, n = str(), 0, 0
  for byte in binary:
    b |= ord(byte) << n
    n += 8
    if n>13:
      v = b & 8191
      if v > 88:
        b >>= 13
        n -= 13
      else:
        v = b & 16383
        b >>= 14
        n -= 14
      string += chr(v % 91 + 33) + chr(v / 91 + 33)
  if n:
    string += chr(b % 91 + 33)
    if n>7 or b>90:
      string += chr(b / 91 + 33)
  return string

def decode(string):
  binary, v, b, n = str(), -1, 0, 0
  for byte in string:
    c = ord(byte) - 33
    if(v < 0):
      v = c
    else:
      v += c * 91
      b |= v << n
      n += 13 if (v & 8191)>88 else 14
      while 1:
        binary += chr(b & 255)
        b >>= 8
        n -= 8
        if not n>7:
          break
      v = -1
  if v+1:
    binary += chr( (b | v << n) & 255 )
  return binary
