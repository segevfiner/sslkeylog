Welcome to sslkeylog's documentation!
=====================================

.. toctree::
   :hidden:
   :maxdepth: 2

   changelog

This is an implementation of the ``SSLKEYLOGFILE`` facility, available in Firefox and
Chromium/Google Chrome, that is supported by Wireshark in order to decrypt SSL/TLS connections
even when you don't have the private key, or when using key exchange methods that will prevent
decryption even if you do (Such as Diffie-Hellman).

This is for the standard library ``ssl`` module, it won't work for other ssl modules.

.. note::
   Python 3.8+ includes built-in support for generating an SSL key log file via
   :attr:`ssl.SSLContext.keylog_filename`, and will also enable it when the ``SSLKEYLOGFILE``
   environment variable is set when creating a context via :func:`ssl.create_default_context`.

   This package uses the same callback the built-in implementation is using, which will likely cause
   both implementations to trample each other, causing the other not to work, or other unintended
   consequences. As such, you should probably not enable both at the same time.

sslkeylog
---------

.. automodule:: sslkeylog
   :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
