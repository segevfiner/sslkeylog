import pytest
import ssl


@pytest.hookimpl(optionalhook=True)
def pytest_metadata(metadata):
    metadata['OpenSSL'] = ssl.OPENSSL_VERSION
