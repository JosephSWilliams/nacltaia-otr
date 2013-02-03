#include <Python.h>

PyObject *pybase91a(PyObject *self){ /* hack __init__ */
  return Py_BuildValue("i", 0);}

PyObject *pyencode(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:encode", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  unsigned char *out;
  out = PyMem_Malloc(dlen<<1);

  if (!out)
    return PyErr_NoMemory();

  int l = 0; int i = 0; int b = 0; int n = 0; int v = 0;

  for(i=0;i<dlen;++i){
    b |= data[i] << n;
    n += 8;
    if (n>13){
      v = b & 8191;
      if (v>88){
        b >>= 13;
        n -= 13;}
      else {
        v = b & 16383;
        b >>= 14;
        n -= 14;}
      out[l] = v % 91 + 33; ++l;
      out[l] = v / 91 + 33; ++l;}}
  if (n){
    out[l] = b % 91 + 33; ++l;
    if ((n>7)||(b>90)){
      out[l] = b / 91 + 33; ++l;}}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,l);
  PyMem_Free(out);
  return ret;}

PyObject *pydecode(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:decode", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  unsigned char *out;
  out = PyMem_Malloc(dlen);

  if (!out)
    return PyErr_NoMemory();

  int l = 0; int i = 0; int c =  0;
  int b = 0; int n = 0; int v = -1;

  for(i=0;i<dlen;++i){
    c = data[i] - 33;
    if ((c<0)||(c>90)){
      PyMem_Free(out);
      return Py_BuildValue("s", "");}
    if (v<0)
      v = c;
    else {
      v += c * 91;
      b |= v << n;
      if ((v & 8191)>88)
        n += 13;
      else
        n += 14;
      while (1){
        out[l] = b & 255; ++l;
        b >>= 8;
        n -= 8;
        if (n<=7)
          break;}
      v = -1;}}
  if (v+1){
    out[l] = (b | v << n) & 255; ++l;}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,l);
  PyMem_Free(out);
  return ret;}


PyObject *pybin2hex(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:bin2hex", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  unsigned char *out;
  out = PyMem_Malloc(dlen<<1);

  if (!out)
    return PyErr_NoMemory();

  int i = 0; int l = 0;

  for(i=0;i<dlen;++i){
    out[l] = data[i] >> 4;
    if (out[l]<10){
      out[l] += 48;}
    else {
      out[l] += 55;} ++l;

    out[l] = data[i] % 16;
    if (out[l]<10){
      out[l] += 48;}
    else {
      out[l] += 55;} ++l;}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,dlen<<1);
  PyMem_Free(out);
  return ret;}

PyObject *pyhex2bin(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:hex2bin", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  if (dlen%2)
    return Py_BuildValue("s", "");

  unsigned char *out;
  out = PyMem_Malloc(dlen>>1);

  if (!out)
    return PyErr_NoMemory();

  int l = 0; int i = 0;

  for(i=0;i<dlen;++i){
    if ((data[i]>47)&(data[i]<58))
      out[l] = data[i] - 48 << 4;
    else {
      if ((data[i]>64)&(data[i]<71))
        out[l] = data[i] - 55 << 4;
      else {
        if ((data[i]>96)&(data[i]<103))
          out[l] = data[i] - 87 << 4;
        else {
          PyMem_Free(out);
          return Py_BuildValue("s", "");}}}++i;

    if ((data[i]>47)&(data[i]<58))
      out[l] += data[i] - 48;
    else {
      if ((data[i]>64)&(data[i]<71))
        out[l] += data[i] - 55;
      else {
        if ((data[i]>96)&(data[i]<103))
          out[l] += data[i] - 87;
        else {
          PyMem_Free(out);
          return Py_BuildValue("s", "");}}}++l;}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,l);
  PyMem_Free(out);
  return ret;}

static PyMethodDef Module_methods[] = {
  {"base91a", pybase91a, METH_NOARGS},
  {"bin2hex", pybin2hex, METH_VARARGS|METH_KEYWORDS},
  {"hex2bin", pyhex2bin, METH_VARARGS|METH_KEYWORDS},
  {"encode" , pyencode , METH_VARARGS|METH_KEYWORDS},
  {"decode" , pydecode , METH_VARARGS|METH_KEYWORDS},
  {NULL, NULL}};

void initbase91a(){
  (void) Py_InitModule("base91a", Module_methods);}

void initbin2hex(){
  (void) Py_InitModule("bin2hex", Module_methods);}

void inithex2bin(){
  (void) Py_InitModule("hex2bin", Module_methods);}

void initencode(){
  (void) Py_InitModule("encode", Module_methods);}

void initdecode(){
  (void) Py_InitModule("decode", Module_methods);}
