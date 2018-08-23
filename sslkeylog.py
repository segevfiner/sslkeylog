from __future__ import absolute_import
import _sslkeylog


def get_client_random(sock):
    sock = getattr(sock, '_sslobj', sock)
    return _sslkeylog.get_client_random(sock)


def get_master_key(sock):
    sock = getattr(sock, '_sslobj', sock)
    return _sslkeylog.get_master_key(sock)
