#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# Configuration items

from remail.mail import email_addr_valid

import os


class RemailException(Exception):
    pass

class RemailConfigException(RemailException):
    pass

class RemailListConfigException(RemailException):
    pass

def get_mandatory(key, cfgdict, base):
    res = cfgdict.get(key)
    if not res:
        txt = 'Missing config entry: %s.%s' % (base, key)
        raise RemailListConfigException(txt)
    return res

def get_optional(key, defdict, cfgdict):
    return cfgdict.get(key, defdict[key])

def set_defaults(obj, defdict, cfgdict):
    if not cfgdict:
        cfgdict = {}
    for key, val in defdict.items():
        val = cfgdict.get(key, val)
        setattr(obj, key, val)

def show_attrs(obj, attrdict, indent):
    for attr in attrdict:
        print('%*s%-40s: %s' %(indent, '', attr, getattr(obj, attr)))

account_defaults = {
    'enabled'     : False,
    'fingerprint' : None,
    'use_smime'   : False,
    'gpg_plain'   : False,
}

class account_config(object):
    def __init__(self, cfgdict, addr, base):
        base = base + '.addr'
        # Do at least minimal checks for a valid email address
        if not email_addr_valid(addr):
            txt = 'Invalid email address: %s' % base
            raise RemailListConfig_Exception(txt)

        self.addr = addr
        self.name = get_mandatory('name', cfgdict, base)
        set_defaults(self, account_defaults, cfgdict)

        # Get the optional aliases to allow sending from
        # different accounts when the list is moderated
        aliases = cfgdict.get('aliases')
        if not aliases:
            self.aliases = []
        else:
            self.aliases = aliases

    def show(self, indent, all=True):
        print('%*s%-40s: %s' %(indent, '', self.name, self.addr))
        indent += 2
        if all:
            show_attrs(self, account_defaults, indent)
            txt = ''
            for alias in self.aliases:
                txt += '%s ' % alias
            print('%*s%-40s: %s' %(indent, '', 'aliases', txt))
        else:
            print('%*s%-40s: %s' %(indent, '', 'fingerprint', self.fingerprint))

class accounts_config(object):
    def __init__(self, cfgdict, base):
        self.accounts = {}
        for addr, cfg in cfgdict.items():
            account = account_config(cfg, addr, base)
            self.accounts[addr] = account

    def __len__(self):
        return len(self.accounts)

    def has_account(self, addr):
        for account in self.accounts.values():
            if account.addr == addr:
                return True
            if addr in account.aliases:
                return True
        return False

    def get(self, addr):
        return self.accounts.get(addr)

    def keys(self):
        return self.accounts.keys()

    def values(self):
        return self.accounts.values()

    def show(self, indent):
        for addr, acc in self.accounts.items():
            acc.show(indent)

    def pop(self):
        addr, acc = self.accounts.popitem()
        return acc

def list_account_config(cfgdict, base):
    laccs = accounts_config(cfgdict, base)
    if len(laccs) != 1:
        txt = '% entry for %s' % base
        raise RemailListConfigException(txt)
    return laccs.pop()

def build_listheaders(mailaddr):
    addr, domain = mailaddr.split('@')
    headers = {}
    headers['List-Id'] = mailaddr
    headers['List-Owner'] = '<mailto:%s-owner@%s>' % (addr, domain)
    headers['List-Post'] = '<mailto:%s>' % mailaddr
    return headers

class destination(object):
    def __init__(self, toadmin, accounts):
        self.toadmin = toadmin
        self.accounts = accounts

class listaddrs(object):
    '''
    Build an object with the valid list addresses
    addr@domain, addr-owner@domain, addr-bounce@domain
    '''
    def __init__(self, mailaddr):
        addr, domain = mailaddr.split('@')
        self.post = mailaddr
        self.owner = '%s-owner@%s' % (addr, domain)
        self.bounce = '%s-bounce@%s' % (addr, domain)
        # Dictionary to lookup an incoming address
        # and to establish to which target it goes
        # Entry is true if the target is admins
        self.addrs = {}
        self.addrs[self.post] = False
        self.addrs[self.owner] = True
        self.addrs[self.bounce] = True

    def get_destination(self, msgto, admins, subscribers):
        if not msgto in self.addrs.keys():
            return None

        if self.addrs[msgto]:
            return destination(True, admins)
        return destination(False, subscribers)

    def show(self, indent):
        print('%*slistaddrs:' %(indent, ''))
        indent += 2
        print('%*s%-40s: %s' %(indent, '', 'post', self.post))
        print('%*s%-40s: %s' %(indent, '', 'owner', self.owner))
        print('%*s%-40s: %s' %(indent, '', 'bounce', self.bounce))

class archive_config(object):
    def __init__(self, aopts, listdir):
        self.incoming = aopts.incoming
        self.plain = aopts.plain
        self.mdir = aopts.use_maildir
        if self.mdir:
            self.m_encr = os.path.join(listdir, 'archive_encr/')
            self.m_admin = os.path.join(listdir, 'archive_admin/')
            self.m_list = os.path.join(listdir, 'archive_list/')
        else:
            self.m_encr = os.path.join(listdir, 'archive_encr.mbox')
            self.m_admin = os.path.join(listdir, 'archive_admin.mbox')
            self.m_list = os.path.join(listdir, 'archive_list.mbox')

    def show(self, indent):
        print('%*s%-40s: %s' % (indent, '', 'use_maildir', self.mdir))
        if self.incoming:
            print('%*s%-40s: %s' % (indent, '', 'incoming', self.m_encr))
        if self.plain:
            print('%*s%-40s: %s' % (indent, '', 'plain_admin', self.m_admin))
            print('%*s%-40s: %s' % (indent, '', 'plain_list', self.m_list))

smime_defaults = {
    'verify'     : True,
    'sign'       : True,
}

class smime_config(object):
    def __init__(self, listdir, cfgdict):
        set_defaults(self, smime_defaults, cfgdict)
        self.global_certs = '.certs'
        self.ca_certs = os.path.join(self.global_certs, 'cacert.pem')
        self.list_certs = os.path.normpath(os.path.join(listdir, '.certs'))

    def show(self, indent):
        print('%*sS/MIME:' % (indent, ''))
        indent += 2
        show_attrs(self, smime_defaults, indent)
        print('%*s%-40s: %s' %(indent, '', 'global_certs', self.global_certs))
        print('%*s%-40s: %s' %(indent, '', 'ca_certs', self.ca_certs))
        print('%*s%-40s: %s' %(indent, '', 'list_certs', self.list_certs))

gpg_defaults = {
    'always_trust'     : True,
    'sign'             : True,
    'gpgbinary'        : 'gpg',
}

class gpg_config(object):
    def __init__(self, listdir, cfgdict):
        set_defaults(self, gpg_defaults, cfgdict)
        self.armor = True
        self.home = '.gnupg'
        self.keyring = os.path.join(listdir, '.gnupg', 'pubring.kbx')
        self.keyring = os.path.normpath(self.keyring)

    def show(self, indent):
        print('%*sGPG:' % (indent, ''))
        indent += 2
        show_attrs(self, gpg_defaults, indent)
        print('%*s%-40s: %s' %(indent, '', 'home', self.home))
        print('%*s%-40s: %s' %(indent, '', 'keyring', self.keyring))

class tracking_config(object):
    def __init__(self, listdir):
        self.tracking_file = os.path.join(listdir, 'tracking.yaml')

    def show(self, indent):
        print('%*s%-40s: %s' % (indent, '', 'tracking_file', self.tracking_file))

class template_config(object):
    def __init__(self, listdir):
        self.welcome = os.path.join(listdir, 'template_welcome')
        self.admin = os.path.join(listdir, 'template_admin')

    def show(self, indent):
        print('%*stemplates:' % (indent, ''))
        indent += 2
        print('%*s%-40s: %s' %(indent, '', 'welcome', self.welcome))
        print('%*s%-40s: %s' %(indent, '', 'admin', self.admin))

archive_defaults = {
    'incoming'    : True,
    'plain'       : True,
    'use_maildir' : False,
}

class archive_options(object):
    def __init__(self, cfgdict):
        set_defaults(self, archive_defaults, cfgdict)

list_defaults = {
    'enabled'             : False,
    'moderated'           : False,
}

class list_config(object):
    def __init__(self, name, cfgdict):
        base = 'base.lists.%s' %name
        self.base = base
        self.name = name
        set_defaults(self, list_defaults, cfgdict)

        self.listdir = os.path.join('lists', name)
        self.listcfg = os.path.join(self.listdir, 'list.yaml')
        self.tracking = tracking_config(self.listdir)
        self.templates = template_config(self.listdir)
        aopts = archive_options(cfgdict.get('archive', {}))
        self.archives = archive_config(aopts, self.listdir)

        acc = get_mandatory('listaccount', cfgdict, base)
        self.listaccount = list_account_config(acc, base + '.listaccount')

        self.listaddrs = listaddrs(self.listaccount.addr)
        self.listheaders = build_listheaders(self.listaccount.addr)

        self.smime = smime_config(self.listdir, None)
        self.gpg = gpg_config(self.listdir, None)

        self.admins = accounts_config(get_mandatory('admins', cfgdict, base),
                                      base)
        self.subscribers = accounts_config({}, base)

    def config_subscribers(self, cfgdict):
        self.subscribers = accounts_config(cfgdict, self.base)

    def show(self, indent):
        print('%*s%s' %(indent, '', self.name))
        indent += 2
        show_attrs(self, list_defaults, indent)
        print('%*s%-40s: %s' %(indent, '', 'listdir', self.listdir))
        print('%*s%-40s: %s' %(indent, '', 'listcfg', self.listcfg))
        self.tracking.show(indent)
        print('%*sarchive:' %(indent, ''))
        self.archives.show(indent + 2)
        self.smime.show(indent)
        self.gpg.show(indent)
        print('%*slistaccount:' %(indent, ''))
        self.listaccount.show(indent + 2, all=False)
        self.listaddrs.show(indent)
        print('%*slistheaders:' %(indent, ''))
        for h, v in self.listheaders.items():
            print('%*s%-40s: %s' % (indent + 2, '', h, v))

        print('%*sadmins:' %(indent, ''))
        self.admins.show(indent + 2)
        print('%*ssubscribers:' %(indent, ''))
        self.subscribers.show(indent + 2)

main_defaults = {
    'enabled'     : False,
    'use_smtp'    : False,
}

class main_config(object):
    def __init__(self, cfgdict):
        set_defaults(self, main_defaults, cfgdict)
        self.maildir = 'maildir'
        self.mailfrozen = 'maildir.frozen'
        self.lockfile = 'lock'

        self.smime = smime_config('.', cfgdict.get('smime'))
        self.gpg = gpg_config('.', cfgdict.get('gpg'))

        # Configure the lists
        self.lists = []
        for name, l in cfgdict.get('lists', {}).items():
            self.lists.append(list_config(name, l))

    def show(self):
        show_attrs(self, main_defaults, 2)
        print('  %-40s: %s' %('maildir', self.maildir))
        self.smime.show(4)
        self.gpg.show(4)
        print('  lists:')
        for ml in self.lists:
            ml.show(4)
