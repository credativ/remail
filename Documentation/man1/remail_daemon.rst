.. SPDX-License-Identifier: GPL-2.0

.. _remail_daemon_man:

remail_daemon manual page
=========================

Synopsis
--------

**remail_daemon** [*options*] config_file

Description
-----------

:program:`remail_daemon`, The daemon for running an encrypted mailing
list. It reads the configuration file from the command line.


Options
-------

-h, --help
   Show this help message and exit

-s syslog, --syslog
   Use syslog for logging. Default is stderr

-v, --verbose
   Enable verbose logging.

-V, --version
   Display version information


Configuration file
------------------

remail_daemon reads the configuration file which was handed in on the
command line.  The configuration file is a simple yaml file. Non-mandatory
configuration options which are not in the configuration file are set to
the default values.

See the configuration file man page for detailed information.


Work directory
--------------

remail daemon assumes that the configuration file is in the work directory
which has a defined layout and content. The directory structure is
documented in the full remail documentation along with hints how to manage
documentation.


See also
--------
:manpage:`remail.config(5)`
