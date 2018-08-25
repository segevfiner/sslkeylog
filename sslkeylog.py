from __future__ import absolute_import
import ssl
import threading
import binascii
from functools import wraps
import six
import _sslkeylog


class KeyLog(object):
    def __init__(self, f):
        if isinstance(f, six.string_types):
            self._should_close = True
            self.file = open(f, 'a')
        else:
            self._should_close = False
            self.file = f

        self.lock = threading.Lock()

    def close(self):
        if self._should_close:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()

    def add(self, sock):
        with self.lock:
            self.file.write("CLIENT_RANDOM {} {}\n".format(
                binascii.hexlify(get_client_random(sock)).decode("utf-8"),
                binascii.hexlify(get_master_key(sock)).decode("utf-8")))
            self.file.flush()


def get_client_random(sock):
    sock = getattr(sock, '_sslobj', sock)
    return _sslkeylog.get_client_random(sock)


def get_master_key(sock):
    sock = getattr(sock, '_sslobj', sock)
    return _sslkeylog.get_master_key(sock)


_keylog_callback = None


def set_keylog(dest):
    global _keylog_callback

    patch()

    if callable(dest):
        _keylog_callback = dest
    else:
        def _keylog(sock):
            dest.add(sock)

        _keylog_callback = _keylog


_patched = False
_original_do_handshake = None


@wraps(ssl.SSLSocket.do_handshake)
def _do_handshake(self, *args, **kwargs):
    _original_do_handshake(self, *args, **kwargs)

    if _keylog_callback is not None:
        _keylog_callback(self)


def patch():
    global _patched, _original_do_handshake

    if _patched:
        return

    _original_do_handshake = ssl.SSLSocket.do_handshake
    ssl.SSLSocket.do_handshake = _do_handshake

    _patched = True


def unpatch():
    global _patched, _original_do_handshake

    if not _patched:
        return

    ssl.SSLSocket.do_handshake = _original_do_handshake
    _original_do_handshake = None

    _patched = False
