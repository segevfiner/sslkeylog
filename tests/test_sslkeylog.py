import os
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


def test_get_client_random(ssl_client):
    assert sslkeylog.get_client_random(ssl_client)


def test_get_client_random_none():
    with pytest.raises(TypeError):
        sslkeylog.get_client_random(None)


def test_get_client_random_not_a_socket():
    with pytest.raises(TypeError):
        sslkeylog.get_client_random(object())


def test_get_master_key(ssl_client):
    assert sslkeylog.get_master_key(ssl_client)


def test_get_master_key_none():
    with pytest.raises(TypeError):
        sslkeylog.get_master_key(None)


def test_get_master_key_not_a_socket():
    with pytest.raises(TypeError):
        sslkeylog.get_master_key(object())


def test_get_keylog_line(ssl_client):
    assert LOG_LINE_REGEX.search(sslkeylog.get_keylog_line(ssl_client))


def test_set_keylog(tmpdir, context, ssl_server):
    keylog = tmpdir / "sslkeylog.txt"
    sslkeylog.set_keylog(str(keylog))

    with closing(ssl_connect(context)) as s:
        s.sendall(b"hello")
        assert s.recv(1024) == b"hello"

    data = keylog.read_text("utf-8").splitlines()
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

    assert len(keylog_callback.call_args_list) == 2
    for args, kwargs in keylog_callback.call_args_list:
        assert isinstance(args[0], ssl.SSLSocket)
        assert LOG_LINE_REGEX.search(args[1])
