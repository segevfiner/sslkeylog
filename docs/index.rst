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

sslkeylog
---------

.. automodule:: sslkeylog
   :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
