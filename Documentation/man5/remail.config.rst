.. SPDX-License-Identifier: GPL-2.0

.. _remail_daemon_config_man:

remail_daemon.config manual page
================================

Synopsis
--------

remail.yaml
list.yaml

Description
-----------

This manual describes the configuration file format for the remail daemon.

The configuration files are using yaml syntax. There are two types of
configuration files:

1) Base configuration file

   The default configuration file is located in the base configuration
   directory which is also the base work directory.

2) List configuration file

   Per mailing list configuration file.

Non-mandatory options are set to the builtin defaults if they are not
available in the configuration files.

.. _config_dir_struct:

Configuration directory structure
---------------------------------

The configuration directory structure is fixed and looks like this::

  ├── .certs
  │   ├── cacert.pem
  │   ├── list1@your.domain.key
  │   ├── list2@your.domain.key
  │   ├── admin1@some.domain.crt
  │   ├── admin2@other.domain.crt
  ├── .git
  ├── .gnupg
  │   ├── private-keys-v1.d
  │   │   ├── XYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYX1.key
  │   │   ├── YXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXY2.key
  │   ├── pubring.kbx
  ├── lists
  │   ├── list1
  │   │   ├── .certs
  │   │   │   ├── list1@your.domain.crt
  │   │   │   ├── subscr1-1@subscr1.domain.crt
  │   │   │   ├── subscr1-2@subscr2.domain.crt
  │   │   │   ├── admin1@some.domain.crt
  │   │   ├── .git
  │   │   ├── .gnupg
  │   │   │   └── pubring.kbx
  │   │   ├── list.yaml
  │   │   ├── template_admin
  │   │   └── template_welcome
  │   ├── list2
  │   │   ├── .certs
  │   │   │   ├── list2@your.domain.crt
  │   │   │   ├── subscr2-1@subscr1.domain.crt
  │   │   │   ├── subscr2-2@subscr2.domain.crt
  │   │   │   ├── admin2@other.domain.crt
  │   │   ├── .git
  │   │   ├── .gnupg
  │   │   │   └── pubring.kbx
  │   │   ├── list.yaml
  │   │   ├── template_admin
  │   │   └── template_welcome
  ├── lock
  ├── maildir
  │   ├── cur
  │   ├── new
  │   └── tmp
  ├── maildir.frozen
  │   ├── cur
  │   ├── new
  │   └── tmp
  └── remail.yaml

The base directory contains:

  - The main configuration file (remail.yaml).

  - The S/MIME directory (.certs).

    .. warning:: It contains the private S/MIME keys of the lists.

  - The GPG directory (.gnupg).

    .. warning:: It contains the private GPG keys of the lists.

  - The maildir directory to which the incoming mail gets delivered by a
    MTA or MRA.

  - The maildir.frozen directory to which unprocessed or failed mail
    gets moved to.

  - A lock file which can be used to protect a reload against a concurrent
    configuration update.

  - The lists directory under which the list specific configuration directories
    are located.

The list directories contain:

  - The list configuration file (list.yaml)

  - The S/MIME directory (.certs). It contains the public S/MIME keys of the
    list subscribers and of the list itself.

  - The GPG directory (.gnupg). It contains the public GPG keys of the list
    subscribers and of the list itself.


Base configuration items
------------------------

The structure of the base configuration file is::

  .. code-block:: yaml

     enabled:     False
     use_smtp:    False
     smime:
       ...
     gpg:
       ...
     lists:
       list1:
         enabled:     True
	 moderated:   True
	 archive:
	  ...
	 listaccount:
	  ...
	 admins:
	  ad1@min.domain:
	   ...
	  adN@min.domain:
	   ...
       listN:
         ...

Base items:
^^^^^^^^^^^

  .. code-block:: yaml

     enabled:     False
     use_smtp:    False

  enabled:

    Optional item to enable or disable the daemon. If the item is set to
    False then no other options are evaluated and the daemon sleeps waiting
    for termination or reconfiguration. If True, the rest or the options is
    evaluated.

    Optional item which defaults to False

  use_smtp:

    Set to True to enable mail delivery via SMTP to the SMTP server on
    localhost. The SMTP server is responsible for relaying the mails to a
    public mail server. remail does not implement any other transport for
    outgoing mail and the target server is therefore not configurable.

    If False the encrypted mails are delivered to stdout. That's mainly a
    development option which is not meant for production use.

    Optional time which defaults to False


S/MIME options:
^^^^^^^^^^^^^^^
    
  .. code-block:: yaml

     smime:
      enabled:             True
      verify:              True
      sign:                True

  enabled:
   Enable S/MIME processing. If this option is set to False then no attempts
   are made to process S/MIME mails or keys.

  verify:

   When handling S/MIME encrypted mail then the validity of the senders key
   is by default verified against the CA certs. If set to False this
   verification is disabled. Disable this only in extreme situations and
   consider the consequences.

 sign:

  Sign the mails sent to S/MIME recipients with the lists key. Enabled by
  default as this is the recommended way to send S/MIME mail. If disabled
  then the public certificate of the list is not part of the welcome
  message which is sent to new recipients. 

GPG options:
^^^^^^^^^^^^
    
  .. code-block:: yaml

     gpg:
      always_trust:        True
      sign:                True
      gpgbinary:           gpg

  always_trust:

   The public keyring of a list is managed by the list administrator. To
   avoid having to manually tweak the trust DB, it's possible to force
   trust mode on the keyring with this option. Defaults to True as the
   trust establishment is the responsibility of the list administrator
   anyway and setting this to True avoids a lot of pointless manual
   operations.

  sign:

   Sign the mails sent to GPG recipients with the lists key. Enabled by
   default as this is the recommended way to send GPG mail. If disabled then
   the public key of the list is not part of the welcome message which is
   sent to new recipients.

  gpgbinary:

   Path to the GnuPG binary to use, defaults to "gpg".

The mailing lists collection:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

  .. code-block:: yaml

     lists:
       listname:
        ...
       listname:

  lists:

    The opening of the lists map.

The list base configuration:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The list base configuration for each list consists of the following items:

  .. code-block:: yaml

     listname:
      enabled:            True
      moderated:          True
      attach_sender_info: False
      listid:             ...
      archive:
        ...
      listaccount:
        ...
      admins:
        ...

The list base items:
""""""""""""""""""""

  .. code-block:: yaml

     listname:
      enabled:            True
      moderated:          True
      attach_sender_info: False

  enabled:

    If False, the list configuration is disabled. No mail is delivered to this
    list. If True, the list is enabled.

  moderated:

    Optional item to set the list to moderated. It True only subscribers
    are allowed to post to the list either from their subscription address
    or from one of the optional alias mail addresses which are associated
    with a subscriber. Mails from non-subscribers are not delivered to the
    list, they are delivered to the list administrator

  attach_sender_info:

    Collects information about the sender, email-address, encryption method
    and if the mail is signed the GPG key or S/MIME certificate contained
    in the signature. This information is attached to the original mail as
    two seperate attachments (text info and key/certificate) if this is
    enabled and the sender is not subscribed to the list. This is for open
    lists and especially contact points so that the subscribers are able
    to contact the sender.

  listid:

    Optional item to override the default list-id with a custom value.
    Default: list address with the "@" replaced by a period.

The archive section:
""""""""""""""""""""

  .. code-block:: yaml

     archive:
      use_maildir:       True
      archive_incoming:  True
      archive_plain:     False

  use_maildir:

    If True, maildir is the storage format for enabled archives. If False,
    mbox is used.

  archive_incoming:

   If True archive the incoming encrypted mails in the selected storage
   format. The maildir folder name is archive_incoming/. The mbox name is
   archive_incoming.mbox. These files/directories are located in the per
   mailing list configuration/work directory.

  archive_plain:

   If True archive the decrypted mails in the selected storage format. The
   mails are archived in two stores:

    - archive_admin[.mbox] for mails which are directed to the list admins
      either directly or through bounce catching, moderation etc.

    - archive_list[.mbox] for mails which are delivered to the list

The list account section:
"""""""""""""""""""""""""

  .. code-block:: yaml

     listaccount:
      list@mail.domain:
       name:             Clear text name
       fingerprint:      40CHARACTERFINGERPRINT

  The list account's e-mail address is the key item for the name and
  fingerprint options.

  name:

     A clear text name for the list, e.g. incident-17 or whatever sensible
     name is selected. This name is used in From mangling when a list post
     is sent to the subscribers:

       incident-17 for Joe Poster <list@mail.domain>

     From rewriting is used to ensure that replies go only to the list and
     not to some other place. The Reply-To field could be used as well but
     that is not correctly handled by mail clients and users can force
     reply to all nevertheless.

  fingerprint:

     The full 40 character PGP fingerprint of the list key.

.. _list_admin_section:

The list administrators section:
""""""""""""""""""""""""""""""""

  .. code-block:: yaml

     admins:
      admin1@some.domain:
       name:             Clear text name
       fingerprint:      40CHARACTERFINGERPRINT
       enabled:          True
       use_smime:        False
       use_transport:    False
       gpg_plain:        False
      admin2@other.domain:

  name:

    The real user name. Mandatory field

   fingerprint:

     The full 40 character PGP fingerprint of the administrators
     key. Mandatory if the use_smime option is not set.

   enabled:

     Switch to enable/disable the account. Mandatory item.

   use_smime:

     Send S/MIME encrypted mail to the admin if True. Otherwise use
     PGP. Optional, defaults to False.

   use_transport:

     Do not bother with encryption and send plain text messages, i.e. rely
     on the SMTP transport layer encryption. None of the admin messages are
     really confidential.

     This may also be a valid option for some subscribers, for example in
     scenarios where the mail provider manages the subscriber key (sic!)
     and does server side decryption anyway, or when mail is delivered to
     an inbox stored on the same infrastructure as remail itself.
     Not recommended for most cases.

     Optional, defaults to False. Note, this is mutually exclusive with
     the 'use_smime' option.

   gpg_plain:

     If False send mail in the application/pgp-encrypted format. If True
     use the plain/text embedded PGP variant if possible. The latter does
     not work for mails with attachments but for normal plain/text
     conversation this can be requested by a recipient because that's
     better supported in some mail clients. Optional, defaults to False.
       
List configuration items
------------------------

The structure of a list specific configuration file is::

  .. code-block:: yaml

     subscribers:
      subscriber1@some.domain:
       ...
      subscriberN@other.domain:
       ...


The configuration of the subscribers is identical to the configuration of
:ref:`the list administrators section <list_admin_section>` above, but it
allows one additional field:

  .. code-block:: yaml

     subscribers:
      subscriber1@some.domain:
        ...
	aliases:
	 - subscr1@some.domain
	 - subscriber1@other.domain

  aliases:

    The optional aliases item is a list of alias email addresses for a
    subscriber. List mail is always delivered to the subscriber e-mail
    address, but people have often several e-mail addresses covered by
    the same PGP key and post from various addresses. If the list is
    moderated, then the aliases allow posting for subscribers from their
    registered alias addresses. If moderation is disabled the alias list
    is not used at all.


See also
--------
:manpage:`remail_daemon(1)`
:manpage:`remail_chkcfg(1)`
:manpage:`remail_pipe(1)`

