"""
This module provides a facility for logging SSL/TLS keys that can be used for decrypting
SSL/TLS connections.

Quickstart::

    import os
    import sslkeylog

    sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))  # Or directly specify a path

    # Do anything involving SSL (Using the built-in ssl module)

Set the :envvar:`SSLKEYLOGFILE` environment variable if you use it, and set "(Pre)-Master-Secret log
filename" in Wireshark's SSL protocol preferences to the resulting file.
"""

from __future__ import absolute_import
import sys
import atexit
import ssl
import threading
import binascii
from functools import wraps
import _sslkeylog


__version__ = u"0.5.2"


if sys.version_info[0] >= 3:
    string_types = str,
else:
    string_types = basestring,  # noqa: F821


OPENSSL111 = ssl.OPENSSL_VERSION_INFO[:3] >= (1, 1, 1)


def get_client_random(sock):
    """
    Get the client random from an :class:`ssl.SSLSocket` or :class:`ssl.SSLObject`.

    .. note:: Does not work with TLS v1.3+ sockets.
    """
    if sock is None:
        raise TypeError(
            "get_client_random() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.get_client_random(sock)


def get_server_random(sock):
    """
    Get the server random from an :class:`ssl.SSLSocket` or :class:`ssl.SSLObject`.

    .. note:: Does not work with TLS v1.3+ sockets.

    .. versionadded:: 0.4.0
    """
    if sock is None:
        raise TypeError(
            "get_server_random() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.get_server_random(sock)


def get_master_key(sock):
    """
    Get the master key from an :class:`ssl.SSLSocket` or :class:`ssl.SSLObject`.

    .. note:: Does not work with TLS v1.3+ sockets.
    """
    if sock is None:
        raise TypeError(
            "get_master_key() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.get_master_key(sock)


def export_keying_material(sock, length, label, context=None):
    """
    Obtain keying material for application use from an :class:`ssl.SSLSocket` or
    :class:`ssl.SSLObject`.

    .. note:: Does not work with SSL v3.0 or below sockets.

    .. versionadded:: 0.4.0
    """
    if ssl.OPENSSL_VERSION_INFO[:3] < (1, 0, 1):
        raise NotImplementedError("Method not implemented in OpenSSL older than 1.0.1")

    if sock is None:
        raise TypeError(
            "export_keying_material() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.export_keying_material(sock, length, label, context)


def get_keylog_line(sock):
    """
    Generate a key log line from an :class:`ssl.SSLSocket` or :class:`ssl.SSLObject`.

    .. note:: Does not work with TLS v1.3+ sockets.
    """
    return "CLIENT_RANDOM {} {}".format(
        binascii.hexlify(get_client_random(sock)).decode("utf-8"),
        binascii.hexlify(get_master_key(sock)).decode("utf-8"))


_lock = threading.Lock()
_log_file = None


@atexit.register
def _cleanup():
    if _log_file is not None:
        _log_file.close()


def set_keylog(dest):
    """
    Set the key log to *dest* which can be either a path, a file-like object or a callback.

    The key log is process-wide and will log keys for all SSL/TLS connections in the process.

    A callback will be called with the socket, and a key log line which should be written
    to the key log.

    This will apply the monkey patch needed to implement this if it's not already applied,
    see :func:`.patch`.
    """
    global _log_file

    if dest is not None:
        patch()

    if dest is None or callable(dest):
        _sslkeylog._keylog_callback = dest
    else:
        if isinstance(dest, string_types):
            log_file = open(dest, 'a')
        else:
            log_file = dest

        def _keylog(sock, line):
            with _lock:
                log_file.write(line + '\n')
                log_file.flush()

        _sslkeylog._keylog_callback = _keylog

    if _log_file is not None:
        _log_file.close()
        _log_file = None

    if isinstance(dest, string_types):
        _log_file = log_file


_patched = False
_orig_sslsocket_do_handshake = None
_orig_sslobject_do_handshake = None
_orig_sslcontext__new__ = None


@wraps(ssl.SSLSocket.do_handshake)
def _sslsocket_do_handshake(self, *args, **kwargs):
    _orig_sslsocket_do_handshake(self, *args, **kwargs)

    if _sslkeylog._keylog_callback is not None:
        _sslkeylog._keylog_callback(self, get_keylog_line(self))


if hasattr(ssl, 'SSLObject'):
    @wraps(ssl.SSLObject.do_handshake)
    def _sslobject_do_handshake(self, *args, **kwargs):
        _orig_sslobject_do_handshake(self, *args, **kwargs)

        # No need to log again if this SSLObject is owned by an SSLSocket
        if isinstance(self._sslobj.owner, ssl.SSLSocket):
            return

        if _sslkeylog._keylog_callback is not None:
            _sslkeylog._keylog_callback(self, get_keylog_line(self))


@wraps(ssl.SSLContext.__new__)
def _sslcontext__new__(cls, *args, **kwargs):
    self = _orig_sslcontext__new__(cls, *args, **kwargs)
    _sslkeylog.set_keylog_callback(self)
    return self


def patch():
    """Apply the monkey patch used to implement the key log, if not already patched."""
    global _patched
    global _orig_sslsocket_do_handshake, _orig_sslobject_do_handshake, _orig_sslcontext__new__

    if _patched:
        return

    if OPENSSL111:
        _orig_sslcontext__new__ = ssl.SSLContext.__new__
        ssl.SSLContext.__new__ = staticmethod(_sslcontext__new__)
    else:
        _orig_sslsocket_do_handshake = ssl.SSLSocket.do_handshake
        ssl.SSLSocket.do_handshake = _sslsocket_do_handshake

        if hasattr(ssl, 'SSLObject'):
            _orig_sslobject_do_handshake = ssl.SSLObject.do_handshake
            ssl.SSLObject.do_handshake = _sslobject_do_handshake

    _patched = True


def unpatch():
    """Unapply the monkey patch used to implement the key log, if it was applied."""
    global _patched
    global _orig_sslsocket_do_handshake, _orig_sslobject_do_handshake, _orig_sslcontext__new__

    if not _patched:
        return

    if OPENSSL111:
        ssl.SSLContext.__new__ = _orig_sslcontext__new__
        _orig_sslcontext__new__ = None
    else:
        ssl.SSLSocket.do_handshake = _orig_sslsocket_do_handshake
        _orig_sslsocket_do_handshake = None

        if hasattr(ssl, 'SSLObject'):
            ssl.SSLObject.do_handshake = _orig_sslobject_do_handshake
            _orig_sslobject_do_handshake = None

    _patched = False
