import sys
import os
import re
import ssl
from io import open
from setuptools import setup, Extension


with open("sslkeylog.py", "r", encoding="utf-8") as f:
    version = re.search(r'(?m)^__version__ = u"([a-zA-Z0-9.-]+)"', f.read()).group(1)

with open("README.rst", "r", encoding="utf-8") as f:
    long_description = f.read()


if sys.platform == "win32":
    openssl_base_version = re.search(r"^OpenSSL ([0-9.]+)", ssl.OPENSSL_VERSION).group(1)
    if openssl_base_version.startswith("3.0"):
        openssl_version = "3.0.11"
    elif openssl_base_version == "1.1.1":
        openssl_version = "1.1.1c"
    elif openssl_base_version == "1.1.0":
        openssl_version = "1.1.0h"
    elif openssl_base_version == "1.0.2":
        openssl_version = "1.0.2o"
    else:
        raise RuntimeError("Unsupported OpenSSL version")

    openssl_dir = os.path.join("openssl", openssl_version,
                               "amd64" if sys.maxsize > 2**32 else "win32")

    include_dirs = [os.path.join(openssl_dir, "include")]

    if openssl_base_version not in ["1.0.2"]:
        library_dirs = [openssl_dir]
        libraries = ["libssl", "libcrypto"]
    else:
        library_dirs = []
        libraries = []
else:
    include_dirs = []
    library_dirs = []
    libraries = ["ssl", "crypto"]


setup(
    name="sslkeylog",
    version=version,
    author="Segev Finer",
    author_email="segev208@gmail.com",
    description="Log SSL/TLS keys for decrypting SSL/TLS connections",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/segevfiner/sslkeylog",
    project_urls={
        "Documentation": "https://sslkeylog.readthedocs.io/",
        "Issue Tracker": "https://github.com/segevfiner/sslkeylog/issues",
    },
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13"
    ],
    keywords="ssl tls sslkeylogfile",
    zip_safe=False,
    py_modules=["sslkeylog"],
    ext_modules=[
        Extension(
            "_sslkeylog", ["_sslkeylog.c"],
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries),
    ],
    extras_require={
        "dev": [
            "flake8",
            "pytest",
            "pytest-metadata",
            "mock",
            "six",
            "sphinx==5.*;python_version>='3.0'"
        ],
    },
)
