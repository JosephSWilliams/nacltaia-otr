#include <Python.h>

PyObject *pybase91a(PyObject *self){ /* hack __init__ */
  return Py_BuildValue("i", 0);}

PyObject *pyencode(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  unsigned char *out;
  out = PyMem_Malloc(dlen*2);

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
    if ((n>7) | (b>90)){
      out[l] = b / 91 + 33; ++l;}}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,l);
  PyMem_Free(out);
  return ret;}

PyObject *pydecode(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  unsigned char *out;
  out = PyMem_Malloc(dlen);

  if (!out)
    return PyErr_NoMemory();

  int l = 0; int i = 0; int c =  0;
  int b = 0; int n = 0; int v = -1;

  for(i=0;i<dlen;++i){
    c = data[i] - 33;
    if ((c<0) | (c>90)){
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


PyObject *pyhex(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  unsigned char *out;
  out = PyMem_Malloc(dlen*2);

  if (!out)
    return PyErr_NoMemory();

  unsigned char hex[16] = {"0123456789ABCDEF"};
  int l = 0; int i = 0;

  for(i=0;i<dlen;++i){
    out[l] = hex[data[i]>>4]; ++l;
    out[l] = hex[data[i]%16]; ++l;}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,l);
  PyMem_Free(out);
  return ret;}

PyObject *pyunhex(PyObject *self, PyObject *args, PyObject *kw){
  unsigned char *data;
  Py_ssize_t dlen=0;
  static const char *kwlist[] = {"data",0};

  if (!PyArg_ParseTupleAndKeywords(args, kw, "|s#:", (char **)kwlist, &data, &dlen)){
    return (PyObject *)0;}

  if (dlen%2)
    return Py_BuildValue("s", "");

  unsigned char *out;
  out = PyMem_Malloc(dlen/2);

  if (!out)
    return PyErr_NoMemory();

  unsigned char hex[16] = {"0123456789abcdef"};
  unsigned char HEX[16] = {"0123456789ABCDEF"};
  int l = 0; int i = 0; int n = 0;

  while(n<dlen){
    i=-1;
    while(i<16){++i;
      if (hex[i]==data[n]){
        out[l] = i;
        break;}
      if (HEX[i]==data[n]){
        out[l] = i;
        break;}}
    if (i==16){
      PyMem_Free(out);
      return Py_BuildValue("s", "");}
    ++n;

    i=-1;
    while(i<16){++i;
      if (hex[i]==data[n]){
        out[l] = (out[l]<<4)+i; ++l;
        break;}
      if (HEX[i]==data[n]){
        out[l] = (out[l]<<4)+i; ++l;
        break;}}
    if (i==16){
      PyMem_Free(out);
      return Py_BuildValue("s", "");}
    ++n;}

  PyObject *ret;
  ret = PyBytes_FromStringAndSize(out,l);
  PyMem_Free(out);
  return ret;}

static PyMethodDef Module_methods[] = {
  {"base91a", pybase91a, METH_NOARGS},
  {"hex"    , pyhex    , METH_VARARGS|METH_KEYWORDS},
  {"unhex"  , pyunhex  , METH_VARARGS|METH_KEYWORDS},
  {"encode" , pyencode , METH_VARARGS|METH_KEYWORDS},
  {"decode" , pydecode , METH_VARARGS|METH_KEYWORDS},
  {NULL, NULL}};

void initbase91a(){
  (void) Py_InitModule("base91a", Module_methods);}

void inithex(){
  (void) Py_InitModule("hex", Module_methods);}

void initunhex(){
  (void) Py_InitModule("unhex", Module_methods);}

void initencode(){
  (void) Py_InitModule("encode", Module_methods);}

void initdecode(){
  (void) Py_InitModule("decode", Module_methods);}
