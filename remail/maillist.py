#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# Mailing list related code

from remail.mail import msg_set_header, msg_force_msg_id, send_mail
from remail.mail import msg_sanitize_incoming, msg_is_autoreply
from remail.mail import get_raw_email_addr, decode_addrs
from remail.mail import msg_from_string

from remail.smime import smime_crypt, RemailSmimeException
from remail.gpg import gpg_crypt, RemailGPGException
from remail.tracking import account_tracking
from remail.config import accounts_config, gpg_config, smime_config

from email.utils import make_msgid, formatdate
from email.policy import EmailPolicy
from flufl.bounce import all_failures

from ruamel.yaml import YAML

import mailbox
import os

class maillist(object):
    '''
    A class representing a mailing list

    The list is configured by a preconfigured config item.
    '''
    def __init__(self, listcfg, logger, use_smtp):
        self.logger = logger
        self.config = listcfg
        self.enabled = listcfg.enabled
        self.use_smtp = use_smtp

        self.smime = smime_crypt(self.config.smime, self.config.listaccount)
        self.gpg = gpg_crypt(self.config.gpg, self.config.listaccount)

        self.tracking = account_tracking(self.config.tracking, logger)

    def get_name(self):
        return self.config.name

    def start_list(self):
        if not self.config.enabled:
            return

        # Initilize the tracker and get the accounts which want
        # a welcome mail sent to them
        welcome = self.tracking.tracking_init(self.config.subscribers)
        for acc in welcome:
            self.send_welcome_mail(acc)
            # Failure to encrypt to the receipient disables the account
            # temporarily
            if acc.enabled:
                self.tracking.enable_account(acc)

        # If exceptions happened tell the administrator
        self.handle_log()

    def send_plain_mail(self, msg, account):
        '''
        Only ever use for admin mails which contain no content!
        '''
        send_mail(msg, account, self.config.listaddrs.owner,
                  self.config.listaddrs.bounce, {}, self.use_smtp)

    def encrypt(self, msg_plain, account):
        '''
        Encrypt plain text message for the account
        '''
        msg = msg_from_string(msg_plain.as_string())
        if account.use_smime:
            self.smime.encrypt(msg, account)
        else:
            self.gpg.encrypt(msg, account)
        return msg

    def send_encrypted_mail(self, msg_plain, account, mfrom):
        try:
            msg_out = self.encrypt(msg_plain, account)
            send_mail(msg_out, account, mfrom, self.config.listaddrs.bounce,
                      self.config.listheaders, self.use_smtp)
        except (RemailGPGException, RemailSmimeException) as ex:
            '''
            GPG and S/MIME exceptions are not fatal. If they happen
            then in most cases the key/cert is not valid. Freeze the
            subscribers account. The log handling will inform the
            administrator about the problem.
            '''
            txt = 'Failed to encrypt mail to %s' % (account.addr)
            self.logger.log_exception(txt, ex)
            if account in self.config.subscribers.values():
                txt = 'Account frozen: %s\n' % (account.addr)
                self.logger.log_warn(txt)
                account.enabled = False
                self.tracking.freeze_account(account)

    def prepare_mail_msg(self, txt):
        '''
        Prepare a mail message from a string. Used for sending
        template based mails to subscribers and admins.
        '''
        msg = msg_from_string(txt)
        # Force a message id and set the date header
        msg_force_msg_id(msg, self.config.listaddrs.post)
        msg_set_header(msg, 'Date', formatdate())
        return msg

    def send_welcome_mail(self, account):
        # Read the template and replace the optional $NAME
        # placeholder with the subscribers name
        txt = open(self.config.templates.welcome).read()
        txt = txt.replace('$NAME', account.name)
        msg = self.prepare_mail_msg(txt)
        self.send_encrypted_mail(msg, account, self.config.listaddrs.post)

    def archive_mail(self, msg, incoming=False, admin=False):
        '''
        Archive mail depending on configuration.
        '''
        if incoming and self.config.archives.incoming:
            f = self.config.archives.m_encr
        elif admin and self.config.archives.plain:
            f = self.config.archives.m_admin
        elif not admin and self.config.archives.plain:
            f = self.config.archives.m_list
        else:
            return
        if self.config.archives.mdir:
            mbox = mailbox.Maildir(f, create=True)
        else:
            mbox = mailbox.mbox(f, create=True)
        mbox.add(msg)
        mbox.close()

    def decrypt_mail(self, msg):
        '''
        Decrypt mail after sanitizing it from HTML and outlook magic
        and decoding base64 transport.
        '''
        msg_sanitize_incoming(msg)

        msg_plain = self.smime.decrypt(msg)
        if not msg_plain:
            msg_plain = self.gpg.decrypt(msg)
        return msg_plain

    def disable_subscribers(self, addrs, msgid):
        '''
        Disable subscribers in @addrs. Emit a warning when an address is
        newly disabled. Update state tracking.
        Admins are informed via log handling
        '''
        for addr in addrs:
            addr = addr.decode()
            acc = self.config.subscribers.get(addr)
            if acc:
                if acc.enabled:
                    acc.enabled = False
                    txt = 'Freezing account due to permanent failure %s\n' % addr
                    self.logger.log_warn('txt')
                self.tracking.freeze_account(acc)
            else:
                txt = 'Trying to freeze non existing account %s.\n' % addr
                txt += '  Message-ID: %s\n' % msgid
                self.logger.log_warn(txt)

    def modsubject(self, msg, prefix):
        '''
        Add a prefix to the subject. Used for administrator mails to inform
        about the nature of the information, e.g. Moderation, Bounces etc.
        '''
        subj = prefix + msg['Subject']
        msg_set_header(msg, 'Subject', subj)

    def moderate(self, msg, dest):
        '''
        If the list is moderated make sure that the sender of a mail
        is subscribed or an administrator. This checks also aliases.
        '''
        if not self.config.moderated:
            return False

        mfrom = get_raw_email_addr(msg.get('From'))
        r = self.config.subscribers.has_account(mfrom)
        r = r or self.config.admins.has_account(mfrom)
        if not r:
            self.modsubject(msg, '[MODERATED] ')
            dest.toadmins = True
            dest.accounts = self.config.admins

    def check_bounces(self, msg, dest):
        '''
        Catch bounces and autoreply messages.
        '''
        temp_fail, perm_fail = all_failures(msg)

        # Disable all permanent failing addresses
        self.disable_subscribers(perm_fail, msg.get('Message-Id'))

        # If this is a bounce, send it to the admins
        if len(temp_fail) or len(perm_fail):
            if len(temp_fail):
                self.modsubject(msg, '[TEMPFAIL] ')
            if len(perm_fail):
                self.modsubject(msg, '[FROZEN] ')
            dest.toadmins = True
            dest.accounts = self.config.admins

        if msg_is_autoreply(msg):
            self.modsubject(msg, '[AUTOREPLY] ')
            dest.toadmins = True
            dest.accounts = self.config.admins

    def mangle_from(self, msg):
        '''
        Build 'From' string so the original 'From' is 'visible':
        From: $LISTNAME for $ORIGINAL_FROM <$LISTADDRESS>

        If $ORIGINAL_FROM does not contain a name, mangle the email
        address by replacing @ with _at_
        '''
        mfrom = msg.get('From').split('<')[0].replace('@', '_at_').strip()
        return '%s for %s <%s>' % (self.config.name, mfrom,
                                   self.config.listaddrs.post)

    def do_process_mail(self, msg, dest):
        # Archive the incoming mail
        self.archive_mail(msg, incoming=True)
        # Destination was already established. Check for bounces first
        self.check_bounces(msg, dest)
        # Check for moderation
        self.moderate(msg, dest)

        msgid = msg.get('Message-Id', '<No ID>')
        msgto = msg.get('To')

        try:
            msg_plain = self.decrypt_mail(msg)
        except Exception as ex:
            txt = 'Failed to decrypt incoming %s to %s\n' %(msgid, msgto)
            self.logger.log_exception(txt, ex)
            return False

        self.archive_mail(msg_plain, admin=dest.toadmin)

        mfrom = self.mangle_from(msg)

        for account in dest.accounts.values():
            if not account.enabled:
                continue
            self.send_encrypted_mail(msg_plain, account, mfrom)
        return True

    def handle_log(self):
        '''
        If the logger captured warnings send them to the list admin(s)
        '''
        if not len(self.logger.warnings):
            return

        txt = open(self.config.templates.admin).read()
        txt += '\n\n%s' %self.logger.warnings
        msg = self.prepare_mail_msg(txt)

        self.logger.log_debug('Sending warnings to admins\n')

        for account in self.config.admins.values():
            if not account.enabled:
                continue
            # Use the bounce address as from ...
            self.send_plain_mail(msg, account)
        self.logger.warnings = ''

    def process_mail(self, msg, dest):
        txt = 'Processing %s mail: %s\n' %(self.config.name, msg.get('Message-ID'))
        self.logger.log_debug(txt)
        res = self.do_process_mail(msg, dest)
        # Send out any warning which might have happened to the admins
        self.handle_log()
        return res

    def get_destination(self, msg):
        # Handle the case where someone put several addresses on To:
        addrs = decode_addrs(msg['To'])

        for addr in addrs:
            to = get_raw_email_addr(addr)
            dest = self.config.listaddrs.get_destination(to, self.config.admins,
                                                         self.config.subscribers)
            if dest:
                msg_set_header(msg, 'To', to)
                return dest
        return None

    def check_keys(self):
        '''
        Check and validate subscriber keys
        '''
        for account in self.config.subscribers.values():
            if not account.enabled:
                continue
            if not account.use_smime:
                self.gpg.check_key(account)
            else:
                self.smime.check_cert(account)

class maillist_checker(object):
    '''
    Trivial wrapper around the list to check and show the subscriber
    configuration.
    '''
    def __init__(self, configfile, logger):
        self.logger = logger
        try:
            cfgdict = YAML().load(open(configfile))
        except Exception as ex:
            txt = 'Failed to load list configfile %s' %configfile
            logger.log_exception(txt, ex)
            return

        self.accounts = accounts_config(cfgdict.get('subscribers', {}), '')

    def show_config(self):
        if self.accounts:
            print('Subscribers:')
            self.accounts.show(2)

    def show_enabled(self):
        if not self.accounts:
            return

        subs = {}
        for account in self.accounts.values():
            if not account.enabled:
                continue
            subs[account.name] = account.addr

        for name in sorted(subs.keys()):
            print('%-40s %s' %(name, subs[name]))

    def check_keys(self):
        if not self.accounts:
            return

        gpgcfg = gpg_config(os.getcwd(), {})
        gpg = gpg_crypt(gpgcfg, None, checkkey=False)

        smimecfg = smime_config(os.getcwd(), {})
        smime = smime_crypt(smimecfg, None, checkkey=False)

        for account in self.accounts.values():
            if not account.enabled:
                continue
            try:
                if not account.use_smime:
                    gpg.check_key(account)
                else:
                    smime.check_cert(account)
            except Exception as ex:
                self.logger.log(str(ex) + '\n')
