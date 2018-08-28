import os
import re
import threading
import socket
import ssl

import pytest
from six.moves import socketserver

import sslkeylog


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERTFILE = os.path.join(SCRIPT_DIR, 'keycert.pem')
ADDRESS = ('localhost', 1443)


@pytest.fixture(autouse=True)
def socket_timeout():
    socket.setdefaulttimeout(5)
    yield
    socket.setdefaulttimeout(None)


class ThreadingSSLServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, handler_class, context):
        super(ThreadingSSLServer, self).__init__(server_address, handler_class)
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


@pytest.fixture
def ssl_client(context, ssl_server):
    with socket.create_connection(ADDRESS) as sock:
        with context.wrap_socket(sock, server_hostname=ADDRESS[0]) as ssock:
            yield ssock


def test_get_client_random(ssl_client):
    assert sslkeylog.get_client_random(ssl_client)


def test_get_master_key(ssl_client):
    assert sslkeylog.get_master_key(ssl_client)


def test_get_keylog_line(ssl_client):
    assert re.search(r'CLIENT_RANDOM [a-zA-Z0-9]{64} [a-zA-Z0-9]{96}',
                     sslkeylog.get_keylog_line(ssl_client))
