from __future__ import absolute_import
import ssl
import threading
import binascii
from functools import wraps
import _sslkeylog


def get_client_random(sock):
    sock = getattr(sock, '_sslobj', sock)
    return _sslkeylog.get_client_random(sock)


def get_master_key(sock):
    sock = getattr(sock, '_sslobj', sock)
    return _sslkeylog.get_master_key(sock)


def get_keylog_line(sock):
    return "CLIENT_RANDOM {} {}".format(
        binascii.hexlify(get_client_random(sock)).decode("utf-8"),
        binascii.hexlify(get_master_key(sock)).decode("utf-8"))


_keylog_callback = None
_lock = threading.Lock()


def set_keylog(dest):
    global _keylog_callback

    patch()

    if callable(dest):
        _keylog_callback = dest
    else:
        def _keylog(sock, line):
            with _lock:
                dest.write(line + '\n')
                dest.flush()

        _keylog_callback = _keylog


_patched = False
_original_do_handshake = None


@wraps(ssl.SSLSocket.do_handshake)
def _do_handshake(self, *args, **kwargs):
    _original_do_handshake(self, *args, **kwargs)

    if _keylog_callback is not None:
        _keylog_callback(self, get_keylog_line(self))


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
