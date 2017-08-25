pam-imap for 2017+
==================

This is an updated version of pam_imap 0.3.8, taken from
http://pam-imap.sourceforge.net/. See README.z_original for the original
readme.

These files were mostly updated last in 2003, 2004 and imap.c in 2009.
These edits might make it work in 2017 again.

See also: https://github.com/MrDroid/pam_imap


Compiling
---------

Debian install prerequisites: libpam0g-dev libssl-dev libgdbm-dev

.. code-block:: console

    $ ./bootstrap
    $ ./configure CPPFLAGS=-DVERIFY_CERT
    $ make


Building a Debian package with ``gbp``:

.. code-block:: console

    $ git clean -xf
    $ gbp buildpackage -us -uc -sa --git-debian-branch=master \
        --git-upstream-tag='v%(version)s' --git-ignore-new

