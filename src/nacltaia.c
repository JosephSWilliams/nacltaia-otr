#include <nacl/crypto_secretbox.h>
#include <nacl/crypto_box.h>
#include <Python.h>
#include <taia.h>

PyObject *pynacltaia(PyObject *self){
  return Py_BuildValue("i", 0);
}

PyObject *pytaia_now(PyObject *self){

  PyObject *ret;
  unsigned char *tpad;
  tpad = PyMem_Malloc(16);

  taia_now(tpad);
  taia_pack(tpad,tpad);

  ret = PyBytes_FromStringAndSize((char *)tpad,16);

  PyMem_Free(tpad);

  return ret;
}

PyObject *pycrypto_box(PyObject *self, PyObject *args, PyObject *kw){

    char *m, *n, *pk, *sk;
    Py_ssize_t msize=0, nsize=0, pksize=0, sksize=0;
    static const char *kwlist[] = {"m", "n", "pk", "sk", 0};
    unsigned int i;
    PyObject *ret;
    size_t mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#s#:crypto_box",
                                     (char **) kwlist,
                                     &m, &msize,
                                     &n, &nsize,
                                     &pk, &pksize,
                                     &sk, &sksize)){
  return (PyObject *)0;
    }

    if (nsize != crypto_box_NONCEBYTES) return Py_BuildValue("i", 0);
    if (pksize != crypto_box_PUBLICKEYBYTES) Py_BuildValue("i", 0);
    if (sksize != crypto_box_SECRETKEYBYTES) Py_BuildValue("i", 0);

    mlen = msize + crypto_box_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen);
    if (!cpad){
  PyMem_Free(mpad);
  return PyErr_NoMemory();
    }

    for (i = 0;i < crypto_box_ZEROBYTES;++i) mpad[i] = 0;
    for (i = crypto_box_ZEROBYTES;i < mlen;++i) mpad[i] = m[i - crypto_box_ZEROBYTES];

    crypto_box(cpad, mpad, mlen,
  (const unsigned char *) n,
  (const unsigned char *) pk,
  (const unsigned char *) sk
    );

    ret = PyBytes_FromStringAndSize(
  (char *)cpad + crypto_box_BOXZEROBYTES,
  mlen - crypto_box_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

PyObject *pycrypto_box_open(PyObject *self, PyObject *args, PyObject *kw){

    char *c, *n, *pk, *sk;
    Py_ssize_t csize=0, nsize=0, pksize=0, sksize=0;
    static const char *kwlist[] = {"c", "n", "pk", "sk", 0};
    unsigned int i;
    PyObject *ret;
    size_t clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#s#:crypto_box_open",
                                     (char **) kwlist,
                                     &c, &csize,
                                     &n, &nsize,
                                     &pk, &pksize,
                                     &sk, &sksize)){
        return (PyObject *)0;
    }

    if (nsize != crypto_box_NONCEBYTES) return Py_BuildValue("i", 0);
    if (pksize != crypto_box_PUBLICKEYBYTES) return Py_BuildValue("i", 0);
    if (sksize != crypto_box_SECRETKEYBYTES) return Py_BuildValue("i", 0);

    clen = csize + crypto_box_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen);
    if (!cpad){
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0;i < crypto_box_BOXZEROBYTES;++i) cpad[i] = 0;
    for (i = crypto_box_BOXZEROBYTES;i < clen;++i) cpad[i] = c[i - crypto_box_BOXZEROBYTES];

    if (crypto_box_open(mpad,cpad,clen,
                       (const unsigned char *) n,
                       (const unsigned char *) pk,
                       (const unsigned char *) sk
                     ) != 0) {

        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return Py_BuildValue("i", 0);
    }
    if (clen < crypto_box_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return Py_BuildValue("i", 0);
    }

    ret = PyBytes_FromStringAndSize(
  (char *)mpad + crypto_box_ZEROBYTES,
  clen - crypto_box_ZEROBYTES
    );
    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;

}

PyObject *pycrypto_secretbox(PyObject *self, PyObject *args, PyObject *kw){

    char *m, *n, *k;
    Py_ssize_t msize=0, nsize=0, ksize=0;
    static const char *kwlist[] = {"m", "n", "k", 0};
    unsigned int i;
    PyObject *ret;
    size_t mlen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_secretbox",
                                     (char **) kwlist,
                                     &m, &msize,
                                     &n, &nsize,
                                     &k, &ksize)){
  return (PyObject *)0;
    }

    if (nsize != crypto_secretbox_NONCEBYTES) return Py_BuildValue("i", 0);
    if (ksize != crypto_secretbox_KEYBYTES) return Py_BuildValue("i", 0);

    mlen = msize + crypto_secretbox_ZEROBYTES;
    mpad = PyMem_Malloc(mlen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(mlen);
    if (!cpad){
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0;i < crypto_secretbox_ZEROBYTES;++i) mpad[i] = 0;
    for (i = crypto_secretbox_ZEROBYTES;i < mlen;++i) mpad[i] = m[i - crypto_secretbox_ZEROBYTES];

    crypto_secretbox(cpad, mpad, mlen,
  (const unsigned char *) n,
  (const unsigned char *) k
    );

    ret = PyBytes_FromStringAndSize(
  (char *)cpad + crypto_secretbox_BOXZEROBYTES,
  mlen - crypto_secretbox_BOXZEROBYTES
    );

    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

PyObject *pycrypto_secretbox_open(PyObject *self, PyObject *args, PyObject *kw){

    char *c, *n, *k;
    Py_ssize_t csize=0, nsize=0, ksize=0;
    static const char *kwlist[] = {"c", "n", "k", 0};
    unsigned int i;
    PyObject *ret;
    size_t clen;
    unsigned char *mpad;
    unsigned char *cpad;

    if (!PyArg_ParseTupleAndKeywords(args, kw,
                                     "|s#s#s#:crypto_secretbox_open",
                                     (char **) kwlist,
                                     &c, &csize,
                                     &n, &nsize,
                                     &k, &ksize)){
        return (PyObject *)0;
    }

    if (nsize != crypto_secretbox_NONCEBYTES) return Py_BuildValue("i", 0);
    if (ksize != crypto_secretbox_KEYBYTES) return Py_BuildValue("i", 0);

    clen = csize + crypto_secretbox_BOXZEROBYTES;
    mpad = PyMem_Malloc(clen);
    if (!mpad) return PyErr_NoMemory();
    cpad = PyMem_Malloc(clen);
    if (!cpad){
        PyMem_Free(mpad);
        return PyErr_NoMemory();
    }

    for (i = 0;i < crypto_secretbox_BOXZEROBYTES;++i) cpad[i] = 0;
    for (i = crypto_secretbox_BOXZEROBYTES;i < clen;++i) cpad[i] = c[i - crypto_secretbox_BOXZEROBYTES];

    if (crypto_secretbox_open(mpad,cpad,clen,
                       (const unsigned char *) n,
                       (const unsigned char *) k
                     ) != 0) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return Py_BuildValue("i", 0);
    }
    if (clen < crypto_secretbox_ZEROBYTES) {
        PyMem_Free(mpad);
        PyMem_Free(cpad);
        return Py_BuildValue("i", 0);
    }

    ret = PyBytes_FromStringAndSize(
  (char *)mpad + crypto_secretbox_ZEROBYTES,
  clen - crypto_secretbox_ZEROBYTES
    );
    PyMem_Free(mpad);
    PyMem_Free(cpad);
    return ret;
}

static PyMethodDef Module_methods[] = {
  {"nacltaia",             pynacltaia,             METH_VARARGS},
  {"taia_now",             pytaia_now,             METH_VARARGS},
  {"crypto_box",           pycrypto_box,           METH_VARARGS},
  {"crypto_box_open",      pycrypto_box_open,      METH_VARARGS},
  {"crypto_secretbox",     pycrypto_secretbox,     METH_VARARGS},
  {"crypto_secretbox_open",pycrypto_secretbox_open,METH_VARARGS},
  {NULL, NULL}
};

void initnacltaia(){
  (void) Py_InitModule("nacltaia", Module_methods);
}

void inittaia_now(){
  (void) Py_InitModule("taia_now", Module_methods);
}

void initcrypto_box(){
  (void) Py_InitModule("crypto_box", Module_methods);
}

void initcrypto_box_open(){
  (void) Py_InitModule("crypto_box_open", Module_methods);
}

void initcrypto_secretbox(){
  (void) Py_InitModule("crypto_secretbox", Module_methods);
}

void initcrypto_secretbox_open(){
  (void) Py_InitModule("crypto_secretbox_open", Module_methods);
}
