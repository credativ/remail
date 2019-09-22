.. SPDX-License-Identifier: GPL-2.0

.. _remail_installation:

remail installation guide
=========================

General
-------

The recommended installation procedure is via the package management system
of your distribution. Manual installation is surely possible and the
various bits and pieces including their default or recommended locations on
the target are documented in the packaging files.

By default the daemon is disabled as it requires configuration.


Protecting the system
---------------------

Run the list daemon on a machine which is not publicly accessible and
ensure that no untrusted users can access it. It can be run in a VM with
the sole purpose of running the encrypted mailing list. As the private keys
of the list are stored on that machine the setup requires deep
understanding of IT security. It's outside the scope of this documentation
to provide guidance on this.


Dependencies
------------

remail requires Python 3 and depends on the following python packages:

  - python3-M2Crypto
  - python3-gnupg
  - python3-yaml

Note, that on Debian 10 python3-M2Crypto is not available, but can be
installed as a Debian package from the testing repository.

Further the systems needs to have:

  - A mail transport agent which handles the transport of the mails to an
    outgoing SMTP server.

  - A mail retriever agent or some other mechanism which can fetch or
    handle incoming mail and deliver it to remails maildir.

The initial deployment of the list daemon which was used to handle
development of mitigations for embargoed hardware security vulnerabilities
uses postfix and getmail, but that's only one of various possibilites.

As the choice of tools depends on the setup and the situation under which
the system is deployed, there is no documentation provided here. It's a
prerequisite that an administrator who wants to deploy remail is familiar
with these kind of tools.

