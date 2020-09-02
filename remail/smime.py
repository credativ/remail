#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# S/MIME decrypt/encrypt functionality

from remail.mail import msg_set_payload, get_raw_email_addr
from remail.mail import msg_get_payload_as_string, msg_set_header
from remail.mail import msg_from_string, msg_from_bytes

from M2Crypto import SMIME, BIO, Rand, X509
import time
import os

class RemailSmimeException(Exception):
    pass

class smime_sender_info(object):
    def __init__(self, cert):
        self.subject = str(cert.get_subject())
        self.pem = cert.as_pem()

    def get_info(self):
        if self.subject:
            info = '%s\n' % self.subject
        else:
            info = 'No further information available\n'
        return 'S/MIME\n' + info

    def get_file(self):
        if self.pem:
            fname = self.subject.replace('/emailAddress=','').strip()
            fname += '.crt'
            return fname, self.pem, 'application', 'octet-stream'
        return None, None, None, None

class smime_crypt(object):
    def __init__(self, smime_cfg, account, checkkey=True):
        self.config = smime_cfg
        self.smime = SMIME.SMIME()
        self.account = account
        if self.config.verify:
            self.ca_verify = 0
        else:
            self.ca_verify = SMIME.PKCS7_NOVERIFY

        if not checkkey:
            return

        # Make it explode right away if the account key is missing, broken ...
        try:
            self.load_account_key()
        except Exception as ex:
            # SMIME Exceptions are undecodable
            txt = 'key or crt of %s not loadable. %s' % (self.account.addr, ex)
            raise RemailSmimeException(txt)

    def check_cert(self, account):
        addr = account.addr
        crt = os.path.join(self.config.list_certs, addr + '.crt')
        try:
            x509 = X509.load_cert(crt)
            subj = x509.get_subject()
            nbef = x509.get_not_before()
            naft = x509.get_not_after()
        except Exception as ex:
            txt = 'Account %s. ' % account.addr
            txt += 'S/MIME cert %s not loadable' % crt
            raise RemailSmimeException(txt)

        txt = '/emailAddress=%s' %account.addr
        if str(subj) != txt:
            txt = 'Account %s. ' % account.addr
            txt += 'S/MIME cert %s is not matching: %s' % (crt, subj)
            raise RemailSmimeException(txt)

        val = nbef.get_datetime().timestamp()
        now = time.time()
        if now < val:
            txt = 'Account %s. ' % account.addr
            txt += 'S/MIME cert %s not yet valid: %s' % (crt, nbef)
            raise RemailSmimeException(txt)

        val = naft.get_datetime().timestamp()
        now = time.time()
        if now >= val:
            txt = 'Account %s. ' % account.addr
            txt += 'S/MIME cert %s expired: %s' % (crt, nbef)
            raise RemailSmimeException(txt)

    def load_account_key(self):
        addr = self.account.addr
        key = os.path.join(self.config.global_certs, addr + '.key')
        crt = os.path.join(self.config.list_certs, addr + '.crt')
        self.smime.load_key(key, crt)

    def smime_is_multipart_signed(self, msg):
        '''
        Check whether the message is signed must be verified and decoded
        '''
        ct = msg.get_content_type()
        if ct == 'multipart/signed':
            proto = msg.get_param('protocol', '')
            if proto == 'application/x-pkcs7-signature':
                return True
            if proto == 'application/pkcs7-signature':
                return True
        return False

    def smime_must_verify(self, msg):
        '''
        Check whether the message is signed and must be verified and decoded
        '''
        ct = msg.get_content_type()
        if ct == 'application/x-pkcs7-mime' or ct == 'application/pkcs7-mime':
            if msg.get_param('smime-type', '') == 'signed-data':
                return True
        else:
            return self.smime_is_multipart_signed(msg)
        return False

    def smime_verify(self, msg, sinfo):
        '''
        Verify SMIME signed message and return the payload as email.message
        '''
        mfrom = get_raw_email_addr(msg['From'])

        p7_bio = BIO.MemoryBuffer(msg.as_bytes())
        p7, data = SMIME.smime_load_pkcs7_bio(p7_bio)

        sk = p7.get0_signers(X509.X509_Stack())
        sinfo.info = smime_sender_info(sk[0])

        self.smime.set_x509_stack(sk)
        store = X509.X509_Store()
        store.load_info(self.config.ca_certs)
        self.smime.set_x509_store(store)

        msgout = self.smime.verify(p7, data, flags=self.ca_verify)
        msg_set_header(msg, 'Signature-Id', mfrom)
        return msg_from_bytes(msgout)

    def smime_decrypt(self, msg, sinfo):
        '''
        Decrypt SMIME message and replace the payload of the original message
        '''
        self.load_account_key()
        bio = BIO.MemoryBuffer(msg.as_bytes())
        p7, data = SMIME.smime_load_pkcs7_bio(bio)
        msg_plain = msg_from_bytes(self.smime.decrypt(p7))

        # If the message is signed as well get the content
        if self.smime_must_verify(msg_plain):
            msg_set_payload(msg, msg_plain)
            msg_plain = self.smime_verify(msg, sinfo)

        msg_set_payload(msg, msg_plain)

    def do_decrypt(self, msg, sinfo):
        '''
        Try to handle received mail with S/MIME. Return the decoded mail or None
        '''
        if self.smime_is_multipart_signed(msg):
            payload = self.smime_verify(msg, sinfo)
            msg_set_payload(msg, payload)

        ct = msg.get_content_type()
        if ct == 'application/pkcs7-mime' or ct == 'application/x-pkcs7-mime':
            msgout = msg_from_string(msg.as_string())
            self.smime_decrypt(msgout, sinfo)
            return msgout

        elif self.smime_must_verify(msg):
            msgout = msg_from_string(msg.as_string())
            payload = self.smime_verify(msgout, sinfo)
            msg_set_payload(msgout, payload)
            return msgout

        return None

    def decrypt(self, msg, sinfo):
        try:
            envto = msg.get('To', None)
            msgid = msg.get('Message-Id', None)
            res = self.do_decrypt(msg, sinfo)
            # If the message was S/MIME encrypted but not signed
            # set an empty S/MIME sender info
            if res and not sinfo.info:
                sinfo.info = smime_sender_info(None)
            return res
        except SMIME.PKCS7_Error as ex:
            # SMIME Exceptions are undecodable
            txt = 'PKCS7 error when decrypting message '
            txt += '%s to %s: %s' % (msgid, envto, ex)
            raise RemailSmimeException(txt)
        except SMIME.SMIME_Error as ex:
            # SMIME Exceptions are undecodable
            txt = 'SMIME error when decrypting message '
            txt += '%s to %s: %s' % (msgid, envto, ex)
            raise RemailSmimeException(txt)
        except Exception as ex:
            txt = 'Error when decrypting message '
            txt += '%s to %s: %s' % (msgid, envto, ex)
            raise RemailSmimeException(txt)

    def smime_encrypt(self, msg, to):
        '''
        Encrypt a message for a recipient
        '''
        # Extract payload for encryption
        payload = msg_get_payload_as_string(msg).encode()

        # Sign the content if a signer is set
        if self.config.sign:
            self.load_account_key()

            sbuf = BIO.MemoryBuffer(payload)
            # Sigh. sign() defaults to sha1...
            p7 = self.smime.sign(sbuf, algo='sha256')
            sbuf.close()

            buf = BIO.MemoryBuffer()
            self.smime.write(buf, p7)
        else:
            buf = BIO.MemoryBuffer(payload)

        # Load target cert to encrypt to.
        key = os.path.join(self.config.list_certs, to + '.crt')
        x509 = X509.load_cert(key)
        sk = X509.X509_Stack()
        sk.push(x509)
        self.smime.set_x509_stack(sk)
        self.smime.set_cipher(SMIME.Cipher('aes_256_cbc'))

        # Encrypt the buffer.
        p7 = self.smime.encrypt(buf)
        buf.close()
        out = BIO.MemoryBuffer()
        self.smime.write(out, p7)
        encmsg = msg_from_bytes(out.read())
        out.close()

        # Get rid of the old style x-pkcs7 type
        ct = encmsg['Content-Type']
        ct = ct.replace('application/x-pkcs7-mime', 'application/pkcs7-mime')
        msg_set_header(encmsg, 'Content-Type', ct)

        msg_set_payload(msg, encmsg)

    def encrypt(self, msg, account):
        '''
        Encrypt a message for a recipient
        '''
        try:
            msgid = msg.get('Message-Id', None)
            self.smime_encrypt(msg, account.addr)
        except SMIME.PKCS7_Error as ex:
            # SMIME Exceptions are undecodable
            txt = 'PKCS7 error when encrypting message '
            txt += '%s to %s: %s' % (msgid, account.addr, ex)
            raise RemailSmimeException(txt)
        except SMIME.SMIME_Error as ex:
            # SMIME Exceptions are undecodable
            txt = 'SMIME error when encrypting message '
            txt += '%s to %s: %s' % (msgid, account.addr, ex)
            raise RemailSmimeException(txt)
        except Exception as ex:
            txt = 'Error when encrypting message '
            txt += '%s to %s: %s' % (msgid, account.addr, ex)
            raise RemailSmimeException(txt)

