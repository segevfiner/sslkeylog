Changelog
=========

v0.3.0 (2020-07-10)
-------------------

Changed
^^^^^^^
* ``set_keylog(None)`` will no longer trigger monkey patching, making it easier to use it
  conditionally.
* Updated documentation to show how to support ``SSLKEYLOGFILE``.
* Document that some methods don't work with TLS v1.3 as the values they are meant to return
  don't exist anymore in TLS v1.3.

Fixed
^^^^^
* Fix tests when TLS v1.3 is enabled by default.

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
