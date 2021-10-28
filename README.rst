sslkeylog
=========

.. image:: https://img.shields.io/pypi/v/sslkeylog.svg
   :target: https://pypi.org/project/sslkeylog/
   :alt: PyPI

.. image:: https://readthedocs.org/projects/sslkeylog/badge/?version=latest
   :target: https://sslkeylog.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://github.com/segevfiner/sslkeylog/actions/workflows/build-and-test.yml/badge.svg
   :target: https://github.com/segevfiner/sslkeylog/actions/workflows/build-and-test.yml
   :alt: Build & Test Status

This is an implementation of the ``SSLKEYLOGFILE`` facility, available in Firefox and
Chromium/Google Chrome, that is supported by Wireshark in order to decrypt SSL/TLS connections
even when you don't have the private key, or when using key exchange methods that will prevent
decryption even if you do (Such as Diffie-Hellman).

This is for the standard library ``ssl`` module, it won't work for other ssl modules.

**Note:**
   Python 3.8+ includes built-in support for generating an SSL key log file via
   ``ssl.SSLContext.keylog_filename``, and will also enable it when the ``SSLKEYLOGFILE``
   environment variable is set when creating a context via ``ssl.create_default_context``.

   This package uses the same callback the built-in implementation is using, which will likely cause
   both implementations to trample each other, causing the other not to work, or other unintended
   consequences. As such, you should probably not enable both at the same time.

Quick Start
-----------
.. code-block:: python

    import os
    import sslkeylog

    sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))  # Or directly specify a path

    # Do anything involving SSL (Using the built-in ssl module)

Set the ``SSLKEYLOGFILE`` environment variable if you use it, and set "(Pre)-Master-Secret log
filename" in Wireshark's SSL protocol preferences to the resulting file.

Links
-----
* `NSS Key Log Format`_
* `Wireshark - SSL`_

.. _NSS Key Log Format: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
.. _Wireshark - SSL: https://wiki.wireshark.org/SSL

License
-------
MIT License, except OpenSSL which is licensed under it's own license. See LICENSE.txt

This product includes software developed by the OpenSSL Project
for use in the OpenSSL Toolkit (http://www.openssl.org/)
