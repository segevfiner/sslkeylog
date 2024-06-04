#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/ssl.h>

static PyObject *sslcontext_type;
static PyObject *sslsocket_type;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
static int sslkeylog_ex_data_index = -1;
#endif

typedef struct {
    PyObject_HEAD
    SSL_CTX *ctx;
    /* ... */
} PySSLContext;

/* This is an hack to get access to the private SSL* of the Python socket object */
#if PY_MAJOR_VERSION >= 3
typedef struct {
    PyObject_HEAD
    PyObject *Socket; /* weakref to socket on which we're layered */
    SSL *ssl;
    /* ... */
} PySSLSocket;
#elif PY_VERSION_HEX >= 0x02070900
static PyObject *sslkeylog_mod;

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
// On such older Python versions on Windows, OpenSSL was built statically into _ssl.pyd without
// exporting any of its symbols, so we can't call any OpenSSL function, so we reimplement them here,
// luckily the ones we need were simple enough
#ifdef _WIN32
static SSL_SESSION *SSL_get_session(const SSL *ssl)
{
    return ssl->session;
}

// Well, this defeats what this is meant to achieve, comparing the build and runtime version of
// OpenSSL, but not much we can do...
static unsigned long SSLeay(void)
{
    return (SSLEAY_VERSION_NUMBER);
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

size_t SSL_get_server_random(const SSL *ssl, unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return sizeof(ssl->s3->server_random);
    if (outlen > sizeof(ssl->s3->server_random))
        outlen = sizeof(ssl->s3->server_random);
    memcpy(out, ssl->s3->server_random, outlen);
    return outlen;
}

static size_t SSL_SESSION_get_master_key(const SSL_SESSION *session,
                                         unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return session->master_key_length;
    if (outlen > (size_t)session->master_key_length)
        outlen = session->master_key_length;
    memcpy(out, session->master_key, outlen);
    return outlen;
}

#define OpenSSL_version_num SSLeay
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

static PyObject *sslkeylog_get_server_random(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;
    size_t size;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "O!:get_server_random", sslsocket_type, &sslsocket)) {
        return NULL;
    }

    if (!sslsocket->ssl) {
        Py_RETURN_NONE;
    }

    size = SSL_get_server_random(sslsocket->ssl, NULL, 0);
    result = PyBytes_FromStringAndSize(NULL, size);
    if (!result) {
        return NULL;
    }

    SSL_get_server_random(sslsocket->ssl, (unsigned char *)PyBytes_AS_STRING(result), size);

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

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
static PyObject *sslkeylog_export_keying_material(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;
    Py_ssize_t out_length;
    const char *label;
    Py_ssize_t label_length;
    Py_buffer context = {0};
    PyObject *result = NULL;

    if (!PyArg_ParseTuple(args, "O!ns#|z*:export_keying_material", sslsocket_type, &sslsocket,
                          &out_length, &label, &label_length, &context)) {
        return NULL;
    }

    if (!sslsocket->ssl) {
        Py_RETURN_NONE;
    }

    result = PyBytes_FromStringAndSize(NULL, out_length);
    if (!result) {
        goto out;
    }

    if (SSL_export_keying_material(
        sslsocket->ssl,
        (unsigned char *)PyBytes_AS_STRING(result),
        (size_t)out_length,
        label, (size_t)label_length,
        context.buf, context.len, context.buf != NULL) != 1) {
            Py_CLEAR(result);
            PyErr_SetString(PyExc_RuntimeError, "SSL_export_keying_material() failed");
            goto out;
    }

out:
    PyBuffer_Release(&context);

    return result;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
typedef struct {
    PyObject *mod;
} sslkeylog_ex_data;

static void sslkeylog_ex_data_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                  int idx, long argl, void *argp)
{
    sslkeylog_ex_data *ex_data = malloc(sizeof(sslkeylog_ex_data));
    if (!ex_data) {
        return;
    }
    memset(ex_data, 0, sizeof(*ex_data));

    SSL_CTX_set_ex_data(parent, idx, ex_data);
}

static int sslkeylog_ex_data_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                                 void **from_d, int idx, long argl, void *argp)
{
    return 0;
}

static void sslkeylog_ex_data_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                   int idx, long argl, void *argp)
{
    free(ptr);
}

static void keylog_callback(const SSL *ssl, const char *line)
{
    PyGILState_STATE gstate = PyGILState_Ensure();

    sslkeylog_ex_data *ex_data = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), sslkeylog_ex_data_index);

    PyObject *keylog_callback = PyObject_GetAttrString(ex_data->mod, "_keylog_callback");
    if (!keylog_callback) {
        PyErr_Clear();
        goto out;
    }

    if (keylog_callback == Py_None) {
        Py_DECREF(keylog_callback);
        goto out;
    }

    PyObject *result = PyObject_CallFunction(keylog_callback, "Os", Py_None, line);
    Py_DECREF(keylog_callback);
    if (!result) {
        PyErr_PrintEx(0);
    }
    Py_XDECREF(result);

out:
    PyGILState_Release(gstate);
}

static PyObject *sslkeylog_set_keylog_callback(PyObject *m, PyObject *args)
{
    PySSLContext *sslcontext;

    if (!PyArg_ParseTuple(args, "O!:set_keylog_callback", sslcontext_type, &sslcontext)) {
        return NULL;
    }

    sslkeylog_ex_data *ex_data = SSL_CTX_get_ex_data(sslcontext->ctx, sslkeylog_ex_data_index);
#if PY_MAJOR_VERSION >= 3
    ex_data->mod = m;
#else
    ex_data->mod = sslkeylog_mod;
#endif

    SSL_CTX_set_keylog_callback(sslcontext->ctx, keylog_callback);

    Py_RETURN_NONE;
}
#endif

static PyMethodDef sslkeylogmethods[] = {
    {"get_client_random", sslkeylog_get_client_random, METH_VARARGS,
     NULL},
    {"get_server_random", sslkeylog_get_server_random, METH_VARARGS,
     NULL},
    {"get_master_key", sslkeylog_get_master_key, METH_VARARGS,
     NULL},
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    {"export_keying_material", sslkeylog_export_keying_material, METH_VARARGS,
     NULL},
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    {"set_keylog_callback", sslkeylog_set_keylog_callback, METH_VARARGS,
     NULL},
#endif
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
    PyObject *m = NULL;
    PyObject *_ssl;

    if ((OpenSSL_version_num() & 0xFFFFF000) != (OPENSSL_VERSION_NUMBER & 0xFFFFF000)) {
        PyErr_SetString(PyExc_RuntimeError,
            "OpenSSL version mismatch between build and runtime. "
            "Please clear your pip cache and rebuild sslkeylog");
        goto out;
    }

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&sslkeylogmodule);
#else
    m = Py_InitModule("_sslkeylog", sslkeylogmethods);
    sslkeylog_mod = m;
#endif
    if (!m) {
        goto out;
    }

    _ssl = PyImport_ImportModule("_ssl");
    if (!_ssl) {
        Py_CLEAR(m);
        goto out;
    }

    sslcontext_type = PyObject_GetAttrString(_ssl, "_SSLContext");
    if (!sslcontext_type) {
        Py_DECREF(_ssl);
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

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    if (sslkeylog_ex_data_index == -1) {
        sslkeylog_ex_data_index = SSL_CTX_get_ex_new_index(
            0,
            NULL,
            sslkeylog_ex_data_new,
            sslkeylog_ex_data_dup,
            sslkeylog_ex_data_free);
        if (sslkeylog_ex_data_index == -1) {
            Py_CLEAR(m);
            PyErr_SetString(PyExc_RuntimeError, "SSL_CTX_get_ex_new_index() failed");
            goto out;
        }
    }
#endif

    Py_INCREF(Py_None);
    PyModule_AddObject(m, "_keylog_callback", Py_None);

out:
#if PY_MAJOR_VERSION >= 3
    return m;
#else
    return;
#endif
}
