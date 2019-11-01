.. SPDX-License-Identifier: GPL-2.0

.. _remail_chkcfg_man:


remail_chkcfg manual page
=========================

Synopsis
--------

**remail_chkcfg** [*options*] config_file

Description
-----------

:program:`remail_chkcfg`, A program to check and display show the
configuration of a crypto mailing list

It reads the configuration file, verifies for correctness and displays the
resulting aggregated configuration in simple form.

Options
-------

-h, --help
  Show this help message and exit

-e, --enabled
 Show a pretty printed tabular list of names and email addresses of all
 enabled subscribers in a list specific configuration file. Implies -lnq.

-l, --list
 Configuration file is a list specific configuration which contains only
 the subscribers

-n, --nokeys
  Do not check for GPG and S/MIME keys and certs

-q, --quiet
  Quiet mode. Do not show the configuration. Only check for correctness

-v, --verbose
  Enable verbose logging.

-V, --version
   Display version information


Invocation
----------

The program expects a properly populated configuration directory at the
place where the config_file is. If the program is invoked from outside the
configuration directory the program changes into the configuration
directory according to the directory part of the config_file argument.

If the configuration file is the base configuration file the program
expects the list configuration files of the enabled lists to be available
in the lists subdirectory.

If it is invoked with a list specific configuration file it only checks and
shows this part. If not disabled it checks for the availability and validity
of the keys for each subscriber.


See also
--------
:manpage:`remail.config(5)`
