import sys
import os
import re
import ssl

from setuptools import setup, Extension


if sys.platform == 'win32':
    openssl_base_version = re.search(r"^OpenSSL ([0-9.]+)", ssl.OPENSSL_VERSION).group(1)
    if openssl_base_version == "1.1.0":
        openssl_version = "1.1.0h"
    elif openssl_base_version == "1.0.2":
        openssl_version = "1.0.2o"
    else:
        raise RuntimeError("Unsupported OpenSSL version")

    openssl_dir = os.path.join('openssl', openssl_version,
                               'amd64' if sys.maxsize > 2**32 else 'win32')

    include_dirs = [os.path.join(openssl_dir, 'include')]

    if openssl_base_version not in ['1.0.2']:
        library_dirs = [openssl_dir]
        libraries = ['libssl', 'libcrypto']
    else:
        library_dirs = []
        libraries = []
else:
    include_dirs = []
    library_dirs = []
    libraries = ['ssl', 'crypto']


setup(
    name="sslkeylog",
    version="0.1.0",
    author="Segev Finer",
    author_email="segev208@gmail.com",
    zip_safe=False,
    py_modules=["sslkeylog"],
    ext_modules=[
        Extension(
            "_sslkeylog", ["src/_sslkeylog.c"],
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries),
    ],
    extras_require={
        "dev": [
            "flake8",
            "pytest",
        ],
    },
)
