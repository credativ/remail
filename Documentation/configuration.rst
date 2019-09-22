.. SPDX-License-Identifier: GPL-2.0

.. _remail_configuration:

remail configuration guide
==========================

Introduction
------------

The configuration files are simple yaml files which only use the very basic
yaml components. The yaml file does not have a schema yet, but the
configuration parser is doing extensive verification.

See :ref:`remail_daemon_config_man` for a detailed explanation of the
configuration files and the configuration items.

The examples directory in Documentation contains a full dummy configuration
for two lists including fully documented yaml files.

Work directory
--------------

The work directory structure is fixed and is documented in the man page in
the section :ref:`config_dir_struct`.

A comfortable way to manage the configuration is git. The base
configuration directory and the actual list configuration directories are
in separate git trees so that they can be maintained by different people
with different permissions.


Key considerations
------------------

Private keys
^^^^^^^^^^^^

In order to encrypt incoming mail and to sign outgoing mail the list daemon
needs access to the private GPG and S/MIME keys of each list.

The keys must be stored without password.

This is not a security issue because if the keys would have passwords then
the password needs to be part of the configuration file.

If the list configuration or the list server is compromised all bets are
off. Having a password on the keys would not make any difference.

Public keys
^^^^^^^^^^^

The public GPG keys of the subscribers in the mailing list specific keyring
are always trusted by remail. The list administrator is responsible for
verifying the authenticity of the subscribers key, so extensive trust
management does not make sense and just complicates the handling.

remail does not try to update the keyring at any time. This is in the
responsibility of the list administrator. Automatic updates are not a
really good idea in the light of the recent attacks on the PGP
infrastructure.

The public S/MIME certificates are verified against the CA certificates
which are provided and managed by the remail base administrator as part of
the base configuration.

Key storage format
------------------

GPG
^^^

GPG keys are stored using the storage format of gnugp. Create and manage
the private keys and the subscriber keyrings with the GPG tool of your
choice.

S/MIME
^^^^^^

S/MIME .key and .crt files are stored in pem format and have to follow
the following naming convention.

Private keys (list keys):
  email@address.domain.key

Public certificates (list and subscribers):
  email@address.domain.crt

Using git for configuration management
--------------------------------------

As seen above the base configuration directory contains the private keys
for the lists. So the administrator has to ensure that the git repository
which is used to push the configuration to is properly protected. Also the
machine used for updating the base configuration repository should not be
accessible by unpriviledged users.

The incomplete list of things to avoid under all circumstances:

 - Push the base configuration to a public hosted repository server like
   github, gitlab etc.

 - Keep the base configuration on an easy accessible machine if the data is
   not sufficiently protected by encryption

 - Keep the base configuration unencrypted on a backup medium.

The list configuration does not contain strictly secret information, but
the pure existance of an incident list and the list of involved people
might give a hint in which area the handled issue might be. So in general
it is recommended to hide a list configuration repository from public and
unpriviledged access as well, but in case of an leak the potential damage
is way smaller than the one of leaking the base configuration which
contains the private keys.


Base configuration
------------------

To configure the list daemon the following configuration files need to be
created or modified:

 - remail.yaml

remail.yaml:

   The main configuration file for the remail daemon. See
   :ref:`remail_daemon_config_man` for a detailed information of the file.

List configuration
------------------

For each enabled mailing list the following configuration files need to be
created or modified:

 - list.yaml
 - template_welcome
 - template_admin

list.yaml:

   The list specific configuration file for the mailing list. It contains
   the subscriber list.  See :ref:`remail_daemon_config_man` for a detailed
   information of the file.

template_admin:

   The mail template for mail to the list admin(s).

template_welcome:

   The mail template for mail to welcome new subscribers.


Public mail
-----------

Request or configure a user account for receiving list mail. This mail
account acts as a catch all for the list, the list-owner and list-bounce
addresses. If more than one mailing list is served by the list daemon then
the user mail account can receive all mails for the lists. remail finds the
appropriate mailing list for the various addresses.

remail does not retrieve mail from a public mail server as this is outside
the scope of remail and depends on the particular setup. remail expects the
incoming mails to be delivered into a maildir. Tools like getmail,
fetchmail can handle that as well as SMTP servers.


Local mail transport
--------------------

remail delivers the outgoing mail to the local SMTP server. The
configuration for the SMTP server to relay the mails to the public facing
machines is outside the scope of this documentation and depends on the SMTP
server variant you are using.
