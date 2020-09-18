.. SPDX-License-Identifier: GPL-2.0

.. _remail_pipe_man:

remail_pipe manual page
=========================

Synopsis
--------

**remail_pipe** [*options*] config_file

Description
-----------

:program:`remail_pipe`, The pipe script for decrypting incoming mail and
sending it re-encrypted to the subscribers of an encrypted mailing
list. The incoming mail is read from stdin.


Options
-------

-h, --help
   Show this help message and exit

-c, --cfgupdate
   Read the configuration update and do not process mail from stdin. That
   allows to send out welcome mails after a list configuration file was
   updated. Otherwise the welcome mails are delayed until actual mail
   delivery happens. The update and welcome mail processing is serialized
   via the lock file in the working directory; no external serialization
   against a concurrent mail delivery required.

-s syslog, --syslog
   Use syslog for logging. Default is stderr

-v, --verbose
   Enable verbose logging.

-V, --version
   Display version information


Configuration file
------------------

remail_pipe reads the configuration file which was handed in as command
line argument.  The configuration file is a simple yaml file. Non-mandatory
configuration options which are not in the configuration file are set to
the default values.

See the configuration file man page for detailed information.


Work directory
--------------

remail pipe assumes that the configuration file is in the work directory
which has a defined layout and content. The directory structure is
documented in the full remail documentation along with hints how to manage
encrypted mailing lists.

Exit codes
----------

.. list-table::

   * - 0
     - Mail was successfully delivered or config update was successful
   * - 1
     - No enabled mailinglist found for delivery
   * - 2
     - Mail processing incomplete. See log output
   * - 11
     - Configuration error
   * - 12
     - Fatal exception

See also
--------
:manpage:`remail.config(5)`
