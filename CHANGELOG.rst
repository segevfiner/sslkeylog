Changelog
=========

Unreleased
----------

Changed
^^^^^^^
* ``set_keylog(None)`` will no longer trigger monkey patching.
* Updated documentation to show how to support ``SSLKEYLOGFILE``.

v0.2.0 (2019-07-16)
-------------------

Added
^^^^^
* Support for OpenSSL 1.1.1 and TLS 1.3
* Support setting keylog to ``None`` to disable.

Fixed
^^^^^
* Fix tests on Linux.

v0.1.1 (2019-01-24)
-------------------
Fix a broken URL in README.rst.

v0.1.0 (2019-01-24)
-------------------
Initial release.
