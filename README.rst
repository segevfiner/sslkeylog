sslkeylog
=========

.. image:: https://img.shields.io/pypi/v/sslkeylog.svg
   :target: https://pypi.org/project/sslkeylog/
   :alt: PyPI

.. image:: https://readthedocs.org/projects/sslkeylog/badge/?version=latest
   :target: https://sslkeylog.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

This is an implementation of the ``SSLKEYLOGFILE`` facility, available in Firefox and
Chromium/Google Chrome, that is supported by Wireshark in order to decrypt SSL/TLS connections
even when you don't have the private key, or when using key exchange methods that will prevent
decryption even if you do (Such as Diffie-Hellman).

This is for the standard library ``ssl`` module, it won't work for other ssl modules.

Quick Start
-----------
.. code-block:: python

    import sslkeylog

    sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))  # Or directly specify a path

    # Do anything involving SSL (Using the built-in ssl module)

Set the :envvar:`SSLKEYLOGFILE` environment variable if you use it, and set "(Pre)-Master-Secret log
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
