.. SPDX-License-Identifier: GPL-2.0

.. _remail_operation:

remail operation related information
====================================

Mails to list administrators
----------------------------

remail sends mail to the list administrators in case of failures or email
related issues. The mails are either incoming mails or mails composed from
the template_admin file.

The mail subject is marked with a prefix depending on the nature of the
issue:

 - [MODERATED]

   The mail which is sent to the moderator is an incoming list mail from a
   non-subscribed sender. Subject and content are kept intact. The mail is
   sent encrypted.

 - [AUTOREPLY]

   Auto-replies like out of office notifications are catched and forwarded
   to the list administrator. There is no policy to disable subscribers
   built in. This has to be handled by the administrator.

 - [TEMPFAIL]

   Temporary delivery failures which are bounced back from a MTA. The
   affected subscriber account is not disabled. This is informational.

 - [FROZEN]

   A permanent delivery failure or a encryption problem happened.

   The affected subscriber account is frozen due to that. See
   :ref:`subscriber_status` below.

 - Subject taken from the template_admin file

   Mails which are composed from the template file contain internal error
   information about issues which the mail processing triggered. Likely
   causes are encryption/decryption failures.

Fatal issues in the list daemon like failures to connect to the local host
SMTP daemon, file system errors or bugs in the list code which trigger an
exception are not sent to the administrators of a mailing list. These
issues are reported verbosely in syslog and the base administrator needs to
take care of them.

.. _subscriber_status:

Subscriber status
-----------------

remail has subscriber state tracking for each mailing list. The tracking
status is maintained in the file tracking.yaml which is managed by remail
in the mailing list specific directory.

The states are stored in a subscriber email-address mapping. The possible
states are:

  - DISABLED

    The subscriber is disabled in the configuration file.

  - REGISTERED

    The subscriber is enabled in the configuration file, but no welcome
    mail has been sent to the subscriber.

  - ENABLED

    The subscriber is enabled in the configuration file. The welcome
    mail has been sent to the subscriber.

  - FROZEN

    The subscriber is enabled in the configuration file, but the account is
    frozen due to a permanent delivery failure or an internal encryption
    problem.

Unfreeze
^^^^^^^^

To unfreeze a subscriber the subscriber account has to be disabled in the
list configuration file and the list daemon configuration has to be
reloaded. After this the subscriber state is set to DISABLED. Re-enabling
the subscriber in the configuration file and reloading the daemon
configuration re-enables the account.

This is a bit tedious and could be handled by a command mail which is sent
from the list administrator to the list, but that's not yet implemented.

