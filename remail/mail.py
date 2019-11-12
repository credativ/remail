#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# Mail message related code

from email.utils import make_msgid, formatdate
from email.header import Header, decode_header
from email import message_from_string, message_from_bytes
from email.generator import Generator
from email.message import Message, EmailMessage
from email.policy import EmailPolicy

import smtplib
import mailbox
import hashlib
import quopri
import base64
import time
import sys
import re

def sanitize_headers(msg):
    '''
    Sanitize headers by keeping only the ones which are interesting
    and order them as gmail is picky about that for no good reason.
    '''
    headers_order = [
        'Return-Path',
        'Date',
        'From',
        'To',
        'Subject',
        'In-Reply-To',
        'References',
        'User-Agent',
        'MIME-Version',
        'Charset',
        'Message-ID',
        'List-Id',
        'List-Post',
        'List-Owner',
        'Content-Type',
        'Content-Disposition',
        'Content-Transfer-Encoding',
        'Content-Language',
        'Envelope-to',
    ]

    # Get all headers and remove them from the message
    hdrs = msg.items()
    for k in msg.keys():
        del msg[k]

    # Add the headers back in proper order
    for h in headers_order:
        for k, v in hdrs:
            if k.lower() == h.lower():
                msg[k] = v

def send_smtp(msg, to, sender):
    '''
    A dumb localhost only SMTP delivery mechanism. No point in trying
    to implement the world of SMTP again. KISS rules!

    Any exception from the smtp transport is propagated to the caller
    '''
    to = msg['To']
    server = smtplib.SMTP('localhost')
    server.ehlo()
    server.send_message(msg, sender, [to])
    server.quit()

def msg_deliver(msg, account, mfrom, sender, use_smtp):
    '''
    Deliver the message. Replace or set the mandatory headers, sanitize
    and order them properly to make gmail happy.
    '''
    msg_set_header(msg, 'From', encode_addr(mfrom))
    msg_set_header(msg, 'To', encode_addr(account.addr))
    msg_set_header(msg, 'Return-path', sender)
    msg_set_header(msg, 'Envelope-to', get_raw_email_addr(account.addr))

    sanitize_headers(msg)

    # Set unixfrom with the current date/time
    msg.set_unixfrom('From remail ' + time.ctime(time.time()))

    # Send it out
    mout = msg_from_string(msg.as_string().replace('\r\n', '\n'))
    if use_smtp:
        send_smtp(mout, account.addr, sender)
    else:
        print(msg.as_string())

def send_mail(msg_out, account, mfrom, sender, listheaders, use_smtp):
        '''
        Send mail to the account. Make sure that the message
        is correct and all required headers and only necessary
        headers are in the outgoing mail.
        '''
        # Add the list headers
        for key, val in listheaders.items():
            msg_out[key] = val

        msg_deliver(msg_out, account, mfrom, sender, use_smtp)

# Minimal check for a valid email address
re_mail = re.compile('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$')

def email_addr_valid(addr):
    return re_mail.match(addr)

def get_raw_email_addr(addr):
    '''
    Return the raw mail address, name and brackets stripped off.
    '''
    try:
        return addr.split('<')[1].split('>')[0].strip()
    except:
        return addr

re_compress_space = re.compile('\s+')

def decode_hdr(hdr):
    '''
    Decode a mail header with encoding
    '''
    elm = decode_header(hdr.strip())
    res = ''
    for txt, enc in elm:
        # Groan ....
        if enc:
            res += ' ' + txt.decode(enc)
        elif isinstance(txt, str):
            res += ' ' + txt
        else:
            res += ' ' + txt.decode('ascii')
    return re_compress_space.sub(' ', res).strip()

def decode_addrs(hdr):
    '''
    Decode mail addresses from a header and handle encondings
    '''
    addrs = []
    if not hdr:
        return addrs
    parts = re_compress_space.sub(' ', hdr).split(',')
    for p in parts:
        addr = decode_hdr(p)
        addrs.append(addr)
    return addrs

def decode_from(msg):
    '''
    Decode the From header and return it as the topmost element
    '''
    addrs = decode_addrs(str(msg['From']))
    return addrs.get_first()

re_noquote = re.compile('[a-zA-Z0-9_\- ]+')

def encode_hdr(txt):
    try:
        return txt.encode('ascii').decode()
    except:
        txt = txt.encode('UTF-8').decode()

def encode_addr(fulladdr):
    try:
        name, addr = fulladdr.split('<', 1)
        name = name.strip()
    except:
        return fulladdr

    try:
        name = txt.encode('ascii').decode()
        if not re_noquote.fullmatch(name):
            name = '"%s"' %name.replace('"', '')
    except:
        name = Header(name).encode()

    return name + ' <' + addr

def msg_from_string(txt):
    policy = EmailPolicy(utf8=True)
    return message_from_string(txt, policy=policy)

def msg_from_bytes(txt):
    policy = EmailPolicy(utf8=True)
    return message_from_bytes(txt, policy=policy)

def msg_force_msg_id(msg, name):
    # Make sure this has a message ID
    id = msg.get('Message-ID', None)
    if not id:
        id = make_msgid(name.split('@')[0])
        msg_set_header(msg, 'Message-ID', id)

re_rmlfcr = re.compile('[\r\n]')

def msg_set_header(msg, hdr, txt):
    '''
    Set new or replace a message header
    '''
    # Sanitize the header first. Broken Outlook GPG payloads
    # come with wreckaged headers.
    txt = re_rmlfcr.sub(' ', txt)

    for k in msg.keys():
        if hdr.lower() == k.lower():
            msg.replace_header(k, txt)
            return
    # Not found set new
    msg[hdr] = txt

payload_valid_mime_headers = [
    'Content-Description',
    'Content-Transfer-Encoding',
    'Content-Disposition',
    'Content-Language',
    'Content-Type',
    'Charset',
    'Mime-Version',
]

def is_payload_header(hdr):
    for h in payload_valid_mime_headers:
        if h.lower() == hdr.lower():
            return True
    return False

def msg_set_payload(msg, payload):
    '''
    Set the payload of a message.
    '''
    msg.clear_content()

    if payload.get_content_type() == 'text/plain':
        pl = payload.get_content()
        msg.set_content(pl)
    else:
        pl = payload.get_payload()
        for h, val in payload.items():
            if is_payload_header(h):
                msg_set_header(msg, h, val)
        msg.set_payload(pl)

def msg_get_payload_as_string(msg):
    '''
    Get the payload with the associated and relevant headers
    '''
    payload = EmailMessage()
    payload.set_payload(msg.get_payload())

    for h in payload_valid_mime_headers:
        if h in msg.keys():
            payload[h] = msg[h]
        elif h == 'Content-Type':
            # Force Content-Type if not set
            # to avoid confusing gmail
            payload[h] = 'text/plain'

    return payload.as_string()

def msg_set_gpg_payload(msg, encpl, bseed, addpgp=False):
    # Create the message boundary
    boundary = hashlib.sha1('.'.join(bseed).encode()).hexdigest() + '-' * 3

    content = '--%s\n' % boundary
    content += 'Content-Type: application/pgp-encrypted\n'
    content += 'Content-Disposition: attachment\n\n'
    content += 'Version: 1\n\n'
    content += '--%s\n' % boundary
    content += 'Content-Type: application/octet-stream\n'
    content += 'Content-Disposition: attachment; filename="msg.asc"\n\n'
    if addpgp:
        content += '-----BEGIN PGP MESSAGE-----\n\n'
    content += encpl + '\n'
    if addpgp:
        content += '-----END PGP MESSAGE-----\n\n'

    msg_set_payload(msg, msg_from_string(content))
    msg_set_header(msg, 'Mime-Version', '1')
    msg_set_header(msg, 'Content-Type',
                   'multipart/encrypted; protocol="application/pgp-encrypted";boundary="%s"' % (boundary))
    msg_set_header(msg, 'Content-Disposition', 'inline')

def msg_strip_signature(msg):
    '''
    Strip signature from msg for now. The formats are horribly different
    and proper encrypted mails are signed as part of the encryption.
    '''
    ct = msg.get_content_type()
    if ct != 'multipart/signed':
        return msg

    boundary = msg.get_boundary(None)
    payload = msg.get_payload()
    stripped = False

    for m in payload:
        if m.get_content_type() == 'application/pgp-signature':
            payload.remove(m)
            stripped = True

    # If no signature found return unmodified msg
    if not stripped:
        return

    if len(payload) == 1:
        # If the remaining message is only a single item set it as payload
        msg_set_payload(msg, payload[0])
    else:
        # Recreate the multipart message
        content = 'Content-type: multipart/mixed; boundary="%s"\n\n' % boundary
        for m in payload:
            content += '--%s\n' % boundary
            content += m.as_string()
            content += '\n'
        content += '--%s\n' % boundary
        msg_set_payload(msg, msg_from_string(content))

def msg_strip_html(msg):
    '''
    Strip html from msg
    '''

    ct = msg.get_content_type()
    if ct != 'multipart/alternative':
        return

    boundary = msg.get_boundary(None)
    payload = msg.get_payload()
    stripped = False

    for m in payload:
        if m.get_content_type() == 'text/html':
            payload.remove(m)
            stripped = True

    # If no html found return
    if not stripped:
        return

    if len(payload) == 1:
        # If the remaining message is only a single item set it as payload
        msg_set_payload(msg, payload[0])
    else:
        # Recreate the multipart message
        content = 'Content-type: multipart/mixed; boundary="%s"\n\n' % boundary
        for m in payload:
            content += '--%s\n' % boundary
            content += m.as_string()
            content += '\n'
        content += '--%s\n' % boundary
        msg_set_payload(msg, msg_from_string(content))

def msg_sanitize_outlook(msg):
    '''
    Oh well ...
    '''
    ct = msg.get_content_type()
    if ct != 'multipart/mixed':
        return

    # The bogus outlook mails consist of a text/plain and an attachment
    payload = msg.get_payload()
    if len(payload) != 2:
        return

    if payload[0].get_content_type() != 'text/plain':
        return

    if payload[1].get_content_type() != 'application/octet-stream':
        return

    fname = payload[1].get_filename(None)
    if not fname:
        return

    if fname not in ['msg.gpg', 'msg.asc', 'GpgOL_MIME_structure.txt']:
        return

    encpl = payload[1].get_payload()
    msg_set_gpg_payload(msg, encpl, 'outlook', addpgp=True)

def decode_base64(msg):
    #
    # Decode base64 encoded text/plain sections
    #
    if msg.get('Content-Transfer-Encoding', '') == 'base64':
        dec = base64.decodestring(msg.get_payload().encode())
        msg.set_payload(dec)
        del msg['Content-Transfer-Encoding']

def decode_alternative(msg):
    '''
    Deal with weird MUAs which put the GPG encrypted text/plain
    part into a multipart/alternative mail.
    '''
    ct = msg.get_content_type()
    if ct == 'multipart/alternative':
        payloads = msg.get_payload()
        payldec = []
        for pl in payloads:
            ct = pl.get_content_type()
            if ct == 'text/plain':
                pl = decode_base64(pl)
            payldec.append(pl)
        msg.set_payload(payldec)
    elif ct == 'text/plain':
        decode_base64(msg)

def msg_sanitize_incoming(msg):
    '''
    Get rid of HMTL, outlook, alternatives etc.
    '''
    # Strip html multipart first
    msg_strip_html(msg)

    # Sanitize outlook crappola
    msg_sanitize_outlook(msg)

    # Handle mutlipart/alternative and base64 encodings
    decode_alternative(msg)

re_noreply = re.compile('^no.?reply@')

def msg_is_autoreply(msg):
    '''
    Check whether a message is an autoreply
    '''
    # RFC 3834
    ar = msg.get('Auto-Submitted')
    if ar and ar != 'no':
        return True

    # Microsoft ...
    ar = msg.get('X-Auto-Response-Suppress')
    if ar in ('DR', 'AutoReply', 'All'):
        return True

    # precedence auto-reply
    if msg.get('Precedence', '') == 'auto-reply':
        return True

    # Reply-To is empty
    rt = msg.get('Reply-To')
    if rt:
        rt = rt.strip()
        if len(rt) == 0:
            return True

        if rt == '<>':
            return True

        # Reply-To matches no_reply, no-reply, noreply
        if re_noreply.search(rt):
            return True

    # Catch empty return path
    rp = msg.get('Return-Path')
    if not rp or rp == '<>':
        return True

    return False
