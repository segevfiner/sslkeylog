import sys
import os
import time
import re
import threading
import socket
import ssl
from contextlib import closing

import pytest
from mock import Mock
from six.moves import socketserver

import sslkeylog


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERTFILE = os.path.join(SCRIPT_DIR, 'keycert.pem')
ADDRESS = ('localhost', 1443)

LOG_LINE_REGEX = re.compile(r'CLIENT_RANDOM [a-zA-Z0-9]{64} [a-zA-Z0-9]{96}')


@pytest.fixture(autouse=True)
def socket_timeout():
    socket.setdefaulttimeout(5)
    yield
    socket.setdefaulttimeout(None)


class ThreadingSSLServer(socketserver.ThreadingTCPServer):
    if sys.platform != 'win32':
        allow_reuse_address = True

    def __init__(self, server_address, handler_class, context):
        socketserver.ThreadingTCPServer.__init__(self, server_address, handler_class)
        self.context = context
        self.socket = self.context.wrap_socket(self.socket, server_side=True)

    def serve_forever_bg(self):
        self.thread = threading.Thread(name="ThreadingSSLServer", target=self.serve_forever)
        self.thread.start()


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(1024)
            if not data:
                return
            self.request.sendall(data)


@pytest.fixture
def ssl_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(CERTFILE)

    server = ThreadingSSLServer(ADDRESS, EchoHandler, context)
    server.serve_forever_bg()

    yield server

    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session", autouse=True)
def patch():
    sslkeylog.patch()
    yield
    sslkeylog.unpatch()


@pytest.fixture
def context():
    return ssl.create_default_context(cafile=CERTFILE)


def ssl_connect(context):
    sock = socket.create_connection(ADDRESS)
    return context.wrap_socket(sock, server_hostname=ADDRESS[0])


@pytest.fixture
def ssl_client(context, ssl_server):
    with closing(socket.create_connection(ADDRESS)) as sock:
        with closing(context.wrap_socket(sock, server_hostname=ADDRESS[0])) as ssock:
            yield ssock


@pytest.fixture
def ssl_client12(ssl_server):
    context = ssl.create_default_context(cafile=CERTFILE)
    if hasattr(context, 'maximum_version'):
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1_3

    with closing(socket.create_connection(ADDRESS)) as sock:
        with closing(context.wrap_socket(sock, server_hostname=ADDRESS[0])) as ssock:
            yield ssock


def test_get_client_random(ssl_client12):
    assert sslkeylog.get_client_random(ssl_client12)


def test_get_client_random_none():
    with pytest.raises(TypeError):
        sslkeylog.get_client_random(None)


def test_get_client_random_not_a_socket():
    with pytest.raises(TypeError):
        sslkeylog.get_client_random(object())


def test_get_server_random(ssl_client12):
    assert sslkeylog.get_server_random(ssl_client12)


def test_get_server_random_none():
    with pytest.raises(TypeError):
        sslkeylog.get_server_random(None)


def test_get_server_random_not_a_socket():
    with pytest.raises(TypeError):
        sslkeylog.get_server_random(object())


def test_get_master_key(ssl_client12):
    assert sslkeylog.get_master_key(ssl_client12)


def test_get_master_key_none():
    with pytest.raises(TypeError):
        sslkeylog.get_master_key(None)


def test_get_master_key_not_a_socket():
    with pytest.raises(TypeError):
        sslkeylog.get_master_key(object())


def test_export_keying_material(ssl_client12):
    assert sslkeylog.export_keying_material(ssl_client12, 32, "EXPERIMENTAL-test")


def test_export_keying_material_with_context(ssl_client12):
    assert sslkeylog.export_keying_material(ssl_client12, 32, "EXPERIMENTAL-test", b"test")


def test_export_keying_material_none():
    with pytest.raises(TypeError):
        sslkeylog.export_keying_material(None, 32, "EXPERIMENTAL-test")


def test_export_keying_material_not_a_socket():
    with pytest.raises(TypeError):
        sslkeylog.export_keying_material(object(), 32, "EXPERIMENTAL-test")


def test_get_keylog_line(ssl_client12):
    assert LOG_LINE_REGEX.search(sslkeylog.get_keylog_line(ssl_client12))


def test_set_keylog(tmpdir, context, ssl_server):
    keylog = tmpdir / "sslkeylog.txt"
    sslkeylog.set_keylog(str(keylog))

    with closing(ssl_connect(context)) as s:
        s.sendall(b"hello")
        assert s.recv(1024) == b"hello"

    data = keylog.read_text("utf-8").splitlines()
    if sslkeylog.OPENSSL111:
        assert len(data) == 10
    else:
        assert len(data) == 2
        for line in data:
            assert LOG_LINE_REGEX.search(line)


def test_set_keylog_unset(tmpdir, context, ssl_server):
    keylog = tmpdir / "sslkeylog.txt"
    sslkeylog.set_keylog(str(keylog))

    with closing(ssl_connect(context)) as s:
        s.sendall(b"hello")
        assert s.recv(1024) == b"hello"

    data = keylog.read_text("utf-8").splitlines()
    if sslkeylog.OPENSSL111:
        assert len(data) == 10
    else:
        assert len(data) == 2
        for line in data:
            assert LOG_LINE_REGEX.search(line)

    sslkeylog.set_keylog(None)

    with closing(ssl_connect(context)) as s:
        s.sendall(b"hello")
        assert s.recv(1024) == b"hello"

    data = keylog.read_text("utf-8").splitlines()
    if sslkeylog.OPENSSL111:
        assert len(data) == 10
    else:
        assert len(data) == 2
        for line in data:
            assert LOG_LINE_REGEX.search(line)


def test_set_keylog_file(tmpdir, context, ssl_server):
    keylog = tmpdir / "sslkeylog.txt"

    with keylog.open('a') as f:
        sslkeylog.set_keylog(f)

        with closing(ssl_connect(context)) as s:
            s.sendall(b"hello")
            assert s.recv(1024) == b"hello"

        data = keylog.read_text("utf-8").splitlines()
        if sslkeylog.OPENSSL111:
            assert len(data) == 10
        else:
            assert len(data) == 2
            for line in data:
                assert LOG_LINE_REGEX.search(line)

        sslkeylog.set_keylog(None)
        assert not f.closed


def test_set_keylog_callback(tmpdir, context, ssl_server):
    keylog_callback = Mock()
    sslkeylog.set_keylog(keylog_callback)

    with closing(ssl_connect(context)) as s:
        s.sendall(b"hello")
        assert s.recv(1024) == b"hello"

    if sslkeylog.OPENSSL111:
        assert len(keylog_callback.call_args_list) == 10
    else:
        assert len(keylog_callback.call_args_list) == 2
        for args, kwargs in keylog_callback.call_args_list:
            assert isinstance(args[0], ssl.SSLSocket)
            assert LOG_LINE_REGEX.search(args[1])


def ssl_io_loop(sock, incoming, outgoing, func, *args):
    while True:
        errno = None
        try:
            ret = func(*args)
        except ssl.SSLError as e:
            if e.errno not in (ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE):
                raise
            errno = e.errno

        buf = outgoing.read()
        sock.sendall(buf)

        if errno is None:
            break
        elif errno == ssl.SSL_ERROR_WANT_READ:
            buf = sock.recv(4096)
            if buf:
                incoming.write(buf)
            else:
                incoming.write_eof()

    return ret


@pytest.mark.skipif(not hasattr(ssl, 'MemoryBIO'), reason="MemoryBIO unsupported")
def test_set_keylog_bio(tmpdir, context, ssl_server):
    keylog = tmpdir / "sslkeylog.txt"
    sslkeylog.set_keylog(str(keylog))

    with closing(socket.create_connection(ADDRESS)) as sock:
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        sslobj = context.wrap_bio(incoming, outgoing, server_side=False,
                                  server_hostname=ADDRESS[0])

        ssl_io_loop(sock, incoming, outgoing, sslobj.do_handshake)

    time.sleep(2)

    data = keylog.read_text("utf-8").splitlines()
    if sslkeylog.OPENSSL111:
        assert len(data) == 10
    else:
        assert len(data) == 2
        for line in data:
            assert LOG_LINE_REGEX.search(line)
