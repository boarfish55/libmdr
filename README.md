OVERVIEW
========
Minimal Data Representation (libmdr) ia a serialization library with
a minimalist wire format and lightweight parser. It's C-friendly, has no
definition language and no code generation tool, using instead
declarations with standard C code in a style reminiscent of
readv()/writev(). There are no optional fields, instead opting to create
new message definitions.

The library comes with a daemon that can handle TLS termination and buffer
messages before passing them to backends over stdin/stdout, similar to
inetd. The split between the daemon and its backend allows for privilege
separation and supports OpenBSD's pledge() & unveil() calls.

It comes with a few extra tools like an indexed heap datastructure, xlog
(extended logging, essentially a syslog wrapper), a TLS event library,
a simple config file handler (flatconf), a fork convenience utility that
can spawn other processes with reduced privileges, and more.

Author: Pascal Lalonde <plalonde@overnet.ca>

See the COPYING file for licensing information.

DISCLAIMER
==========
Use at your own risk. This has not been tested in production.

INSTALLATION & USAGE
====================

Dependencies / license (not including backends):
- libbsd-overlay / libbsd-ctor, if running on Linux (BSD)
- openssl, if running on Linux (Apache 2.0)

On OpenBSD, it only uses what's in the base system (LibreSSL).

KNOWN ISSUES
============
* In mdrd:
    - There are possible deadlock situations if the backend does not
      properly drain STDIN and other error conditions occur.
    - We currently don't deal well with "backpressure" coming from the
      backends to clients, e.g. a high-volume download with a slow
      client.

TODO
====
* Documentation, lots of it
