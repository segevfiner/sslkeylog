import pytest
import ssl


@pytest.mark.optionalhook
def pytest_metadata(metadata):
    metadata['OpenSSL'] = ssl.OPENSSL_VERSION
