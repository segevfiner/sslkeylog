Changelog
=========

v0.5.1 (2024-06-15)
-------------------
Fixed
^^^^^
* Fix build issue due to wrong type of ``sslkeylog_ex_data_dup``
  (`#16 <https://github.com/segevfiner/sslkeylog/pull/16>`_).

v0.5.0 (2023-10-14)
-------------------
Added
^^^^^
* Windows support for Python builds with OpenSSL 3.0

Removed
^^^^^^^
* CI for Python 2.7 & 3.6 as support was removed from GitHub Actions. Though the package itself
  should still work with those versions.

v0.4.0 (2020-10-31)
-------------------

Added
^^^^^
* CI using GitHub Actions. Sadly can't test on Windows Python 2.7 anymore since Microsoft just nuked
  the compilers for it from existence some time ago.
* Added `get_server_random` and `export_keying_material`.
* Add a guard to prevent using sslkeylog with a different version of OpenSSL at runtime then build time.

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
