#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# GPG mail encryption/decryption

from remail.mail import msg_set_payload, msg_set_header
from remail.mail import msg_get_payload_as_string
from remail.mail import msg_from_string, msg_set_gpg_payload

import hashlib
import string
import gnupg
import time
import os

class RemailGPGException(Exception):
    pass

class RemailGPGKeyException(Exception):
    pass

class gpg_crypt(object):
    def __init__(self, gpgcfg, account, checkkey=True):
        self.config = gpgcfg
        self.account = account
        self.gpg = gnupg.GPG(gnupghome=self.config.home,
                             gpgbinary=self.config.gpgbinary,
                             keyring=self.config.keyring)
        self.keys = self.gpg.list_keys()

        if not checkkey:
            return

        self._check_key(self.keys, self.account)
        # Verify that the private key is there as well
        self._check_key(self.gpg.list_keys(True), self.account, private=True)

    def _check_key_addr(self, key, addr):
        maddr = '<%s>' %addr
        maddr = maddr.lower()
        for uid in key['uids']:
            uid = uid.lower()
            if uid.find('<') >= 0:
                if uid.find(maddr) >= 0:
                    return
            elif uid == addr:
                return

        txt = 'Account address/alias %s' % addr
        txt += ' not in GPG key %s\nuids: ' % key['fingerprint']
        for uid in key['uids']:
            txt += ' %s' %uid
        raise RemailGPGKeyException(txt)

    def _check_key_expiry(self, key, addr):
        exp = key['expires']
        if not exp:
            return
        now = time.time()
        if now < float(exp):
            return

        txt = 'Account %s' % addr
        txt += ' GPG key %s expired' % key['fingerprint']
        raise RemailGPGKeyException(txt)

    def _check_key(self, keys, account, private=False):
        for key in keys:
            if account.fingerprint != key['fingerprint']:
                continue

            # Validate that it's the right one
            self._check_key_addr(key, account.addr)
            for alias in account.aliases:
                self._check_key_addr(key, alias)
            self._check_key_expiry(key, account.addr)
            return

        if private:
            txt = 'No private key found for %s' % account.addr
        else:
            txt = 'No public key found for %s' % account.addr
        raise RemailGPGKeyException(txt)

    def check_key(self, account):
        self._check_key(self.keys, account)

    def do_encrypt(self, payload, fingerprints):
        ''' Common encryption helper'''

        if self.config.sign:
            signit = self.account.fingerprint
        else:
            signit = None

        enc = self.gpg.encrypt(payload, fingerprints, armor=self.config.armor,
                               always_trust=self.config.always_trust,
                               sign=signit)
        if enc.ok:
            return str(enc)
        raise RemailGPGException('Encryption fail: %s' % enc.status)

    def gpg_encrypt(self, msg, account):
        ''' Encrypt a message for a subscriber. Depending on the
            subscribers preference, inline it or use the enveloped
            version.
        '''

        fingerprints = [str(account.fingerprint)]
        payload = msg.get_payload()

        # GPG inline encryption magic

        # Use plain GPG if requested by accoung and possible
        isplain = msg.get_content_type() == 'text/plain'
        if account.gpg_plain and type(payload) == str and isplain:
            encpl = self.do_encrypt(payload, fingerprints)
            msg_set_payload(msg, msg_from_string(encpl))
            return msg

        # Extract payload for encryption
        payload = msg_get_payload_as_string(msg)
        encpl = self.do_encrypt(payload, fingerprints)
        msg_set_gpg_payload(msg, encpl, account.addr)
        return msg

    def gpg_decrypt_plain(self, msg):
        '''
        Try to decrypt inline plain/text

        If gpg decrypt returns 'no data was provided' treat the
        message as unencrypted plain text.
        '''
        pl = msg.get_payload(decode=True)
        plain = self.gpg.decrypt(pl, always_trust=self.config.always_trust)
        if plain.ok:
            msg_set_payload(msg, msg_from_string(str(plain)))
            if plain.signature_id:
                msg_set_header(msg, 'Signature-Id', plain.username)
        elif plain.status != 'no data was provided':
            # Check for an empty return path which is a good indicator
            # for a mail server message.
            rp = msg.get('Return-path')
            if rp and rp != '<>':
                raise RemailGPGException('Decryption failed: %s' % plain.status)
        return msg

    def gpg_decrypt_enveloped(self, msg):
        '''
        Try to decrypt an enveloped mail
        '''
        contents = msg.get_payload()
        proto = msg.get_param('protocol')
        if proto != 'application/pgp-encrypted':
            raise RemailGPGException('PGP wrong protocol %s' % proto)
        if len(contents) != 2:
            raise RemailGPGException('PGP content length %d' % len(contents))
        ct = contents[0].get_content_type()
        if ct != 'application/pgp-encrypted':
            raise RemailGPGException('PGP wrong app type %s' % ct)
        ct = contents[1].get_content_type()
        if ct != 'application/octet-stream':
            raise RemailGPGException('PGP wrong app type %s' % ct)

        plain = self.gpg.decrypt(contents[1].get_payload(decode=True),
                                 always_trust=self.config.always_trust)
        if not plain.ok:
            raise RemailGPGException('Decryption failed: %s' % plain.status)

        if plain.signature_id:
            msg_set_header(msg, 'Signature-Id', plain.username)

        pl = msg_from_string(str(plain))
        msg_set_payload(msg, pl)
        return msg

    def decrypt(self, msg):
        '''
        Try to handle received mail with PGP. Return decoded or plain mail
        '''
        msgout = msg_from_string(msg.as_string())
        ct = msg.get_content_type()

        if ct == 'text/plain':
            return self.gpg_decrypt_plain(msgout)

        elif ct == 'multipart/encrypted':
            return self.gpg_decrypt_enveloped(msgout)

        # There might be inline PGP with no mentioning in the content type
        if not msg.is_multipart():
            return msgout

        payloads = msgout.get_payload()
        payldecr = []
        for pl in payloads:
            pl = self.decrypt(pl)
            payldecr.append(pl)
        msgout.set_payload(payldecr)
        return msgout

    def encrypt(self, msg, account):
        '''
        Encrypt a message for a recipient
        '''
        return self.gpg_encrypt(msg, account)

