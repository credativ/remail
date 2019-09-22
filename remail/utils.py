#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# Utilities, RemailException and assorted stuff

import traceback
import syslog
import time
import sys
import os

class RemailException(Exception):
    pass

class logger(object):
    '''
    Logger implementation which can log on stderr or syslog
    and provides a verbose mode to emit debug log messages

    Warnings and exceptions are recorded in an internal buffer
    which can be sent via mail to the admin(s)
    '''
    def __init__(self, use_syslog=False, verbose=False):
        self.use_syslog = use_syslog
        self.verbose = verbose
        self.warnings = ''
        self.exceptions = ''
        self.syslog_warn = syslog.LOG_MAIL | syslog.LOG_WARNING
        self.syslog_info = syslog.LOG_MAIL | syslog.LOG_INFO
        self.syslog_debug = syslog.LOG_MAIL | syslog.LOG_DEBUG

    def log_debug(self, txt):
        '''
        Debug log. Only active if verbose mode is enabled.
        Content is not recorded.
        '''
        if self.verbose:
            if self.use_syslog:
                syslog.syslog(self.syslog_debug, txt)
            else:
                sys.stderr.write(txt)

    def log(self, txt):
        '''
        Regular info log. Content is not recorded.
        '''
        if self.use_syslog:
            syslog.syslog(self.syslog_info, txt)
        else:
            sys.stderr.write(txt)

    def log_warn(self, txt):
        '''
        Warning log. Content is recorded.
        '''
        self.warnings += txt
        if self.use_syslog:
            syslog.syslog(self.syslog_warn, txt)
        else:
            sys.stderr.write(txt)

    def log_exception(self, txt, ex, verbose=False):
        '''
        Exception log. Content is recorded. In verbose mode the
        traceback is recorded as well.
        '''
        etxt = '%s: %s' % (type(ex).__name__, ex)
        txt = 'REMAIL: %s: %s\n' % (txt, etxt)
        if self.verbose or verbose:
            txt += '%s\n' % (traceback.format_exc())
        self.exceptions += txt
        self.log_warn(txt)

def mergeconfig(key, cfgdict, defcfg, default):
    '''
    Return a merged configuration item.

    @key:     key to look up in @cfgdict and @defcfg
    @cfgdict: Dictionary which can contain @key
    @defcfg:  If not None, it can contain an attr named @key
    @default: Used if neither @cfgdict nor @defcfg provide an answer

    If @defcfg is not None, then the attr named @key is queried. If
    available it replaces @default.

    If @key is in @cfgdict, then the value from @cnfdict is returned
    otherwise the default
    '''
    if defcfg:
        default = getattr(defcfg, key, default)
    return cfgdict.get(key, default)

def makepath(base, path):
    '''
    Returns a path built from @base and @path.

    If @path is an absolute path, it is returned unmodified
    If @path is a relative path, it is appended to @base

    Both @base and @path are user expanded, i.e ~/ or ~user/ are
    expanded to absolute pathes
    '''
    path = os.path.expanduser(path)
    if os.path.isabs(path):
        return path

    base = os.path.expanduser(base)
    if not os.path.isabs(base):
        base = os.path.abspath(base)
    return os.path.join(base, path)
