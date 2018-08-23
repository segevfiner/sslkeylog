#include <Python.h>

#include <openssl/ssl.h>

static PyObject *sslsocket_type;

#if PY_MAJOR_VERSION >= 3
typedef struct {
    PyObject_HEAD
    PyObject *Socket; /* weakref to socket on which we're layered */
    SSL *ssl;
    /* ... */
} PySSLSocket;
#else
#error Unsupported Python version
#endif

static PyObject *sslkeylog_get_client_random(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;

    if (!PyArg_ParseTuple(args, "O!:get_client_random", sslsocket_type, &sslsocket)) {
        return NULL;
    }

    if (!sslsocket->ssl) {
        Py_RETURN_NONE;
    }

    unsigned char client_random[SSL3_RANDOM_SIZE];
    size_t size = SSL_get_client_random(sslsocket->ssl, client_random, sizeof(client_random));

    return PyBytes_FromStringAndSize(client_random, size);
}

static PyObject *sslkeylog_get_master_key(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;

    if (!PyArg_ParseTuple(args, "O!:get_master_key", sslsocket_type, &sslsocket)) {
        return NULL;
    }

    if (!sslsocket->ssl) {
        Py_RETURN_NONE;
    }

    SSL_SESSION *session = SSL_get_session(sslsocket->ssl);
    if (!session) {
        Py_RETURN_NONE;
    }

    unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
    size_t size = SSL_SESSION_get_master_key(session, master_key, sizeof(master_key));

    return PyBytes_FromStringAndSize(master_key, size);
}

static PyMethodDef sslkeylogmethods[] = {
    {"get_client_random", sslkeylog_get_client_random, METH_VARARGS,
     NULL},
    {"get_master_key", sslkeylog_get_master_key, METH_VARARGS,
     NULL},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static PyModuleDef sslkeylogmodule = {
    PyModuleDef_HEAD_INIT,
    "_sslkeylog",
    NULL,
    -1,
    sslkeylogmethods
};

PyMODINIT_FUNC PyInit__sslkeylog(void)
#else
PyMODINIT_FUNC init_sslkeylog(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject *m = PyModule_Create(&sslkeylogmodule);
#else
    m = Py_InitModule("_sslkeylog", sslkeylogmethods);
#endif
    if (!m) {
        goto out;
    }

    PyObject *_ssl = PyImport_ImportModule("_ssl");
    if (!_ssl) {
        Py_CLEAR(m);
        goto out;
    }

    sslsocket_type = PyObject_GetAttrString(_ssl, "_SSLSocket");
    if (!sslsocket_type) {
        Py_DECREF(_ssl);
        Py_CLEAR(m);
        goto out;
    }

    Py_DECREF(_ssl);

out:
#if PY_MAJOR_VERSION >= 3
    return m;
#else
    return;
#endif
}
