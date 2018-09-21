#include <Python.h>
#include <openssl/ssl.h>

static PyObject *sslsocket_type;

/* This is an hack to get access to the private SSL* of the Python socket object */
#if PY_MAJOR_VERSION >= 3
typedef struct {
    PyObject_HEAD
    PyObject *Socket; /* weakref to socket on which we're layered */
    SSL *ssl;
    /* ... */
} PySSLSocket;
#elif PY_VERSION_HEX >= 0x02070900
typedef struct PySocketSockObject PySocketSockObject;

typedef struct {
    PyObject_HEAD
    PySocketSockObject *Socket;
    PyObject *ssl_sock;
    SSL *ssl;
    /* ... */
} PySSLSocket;
#else
#error Unsupported Python version
#endif

/* Compatibility for OpenSSL<1.1.0 (Copied from OpenSSL) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef _WIN32
static SSL_SESSION *SSL_get_session(const SSL *ssl)
{
    return ssl->session;
}
#endif

static size_t SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return sizeof(ssl->s3->client_random);
    if (outlen > sizeof(ssl->s3->client_random))
        outlen = sizeof(ssl->s3->client_random);
    memcpy(out, ssl->s3->client_random, outlen);
    return outlen;
}

static size_t SSL_SESSION_get_master_key(const SSL_SESSION *session,
                                         unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return session->master_key_length;
    if (outlen > session->master_key_length)
        outlen = session->master_key_length;
    memcpy(out, session->master_key, outlen);
    return outlen;
}
#endif

static PyObject *sslkeylog_get_client_random(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;
    size_t size;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "O!:get_client_random", sslsocket_type, &sslsocket)) {
        return NULL;
    }

    if (!sslsocket->ssl) {
        Py_RETURN_NONE;
    }

    size = SSL_get_client_random(sslsocket->ssl, NULL, 0);
    result = PyBytes_FromStringAndSize(NULL, size);
    if (!result) {
        return NULL;
    }

    SSL_get_client_random(sslsocket->ssl, (unsigned char *)PyBytes_AS_STRING(result), size);

    return result;
}

static PyObject *sslkeylog_get_master_key(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;
    SSL_SESSION *session;
    size_t size;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "O!:get_master_key", sslsocket_type, &sslsocket)) {
        return NULL;
    }

    if (!sslsocket->ssl) {
        Py_RETURN_NONE;
    }

    session = SSL_get_session(sslsocket->ssl);
    if (!session) {
        Py_RETURN_NONE;
    }

    size = SSL_SESSION_get_master_key(session, NULL, 0);
    result = PyBytes_FromStringAndSize(NULL, size);
    if (!result) {
        return NULL;
    }

    SSL_SESSION_get_master_key(session, (unsigned char *)PyBytes_AS_STRING(result), size);

    return result;
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
    PyObject *m, *_ssl;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&sslkeylogmodule);
#else
    m = Py_InitModule("_sslkeylog", sslkeylogmethods);
#endif
    if (!m) {
        goto out;
    }

    _ssl = PyImport_ImportModule("_ssl");
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
