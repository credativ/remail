#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#

from remail.config import RemailConfigException
from remail.config import main_config
from remail.maillist import maillist

from email import message_from_binary_file, message_from_file
from email.policy import EmailPolicy
from ruamel.yaml import YAML
import pyinotify
import mailbox
import pathlib
import signal
import fcntl
import sys
import os

class EventHandler(pyinotify.ProcessEvent):
    """
    inotify event handler which invokes the mailer function
    to enqueue new mail into the mail process queue
    """
    def __init__(self, mailer):
        self.mailer = mailer
        pass

    def process_IN_CREATE(self, event):
        self.mailer.queue_newmail(event.pathname)
        pass

    def process_IN_MOVED_TO(self, event):
        self.mailer.queue_newmail(event.pathname)
        pass


class remaild(object):
    """
    The remail daemon.
    """
    def __init__(self, cfgfile, logger):
        self.logger = logger
        self.enabled = False

        self.cfgfile = cfgfile
        self.yaml = YAML()

        # Maildir related data
        self.inotifier = None
        self.newmails = []
        self.failedmails = []

        self.policy = EmailPolicy(utf8=True)

        # Mailing lists
        self.mailinglists = []

        # Signals and related data
        self._should_stop = False
        self._should_reload = False
        self.siginstall()

    # Signals
    def term_handler(self, signum, frame):
        '''
        SIGTERM/SIGINT handler. Sets the should stop flag and stops the
        inotifier which brings the inotify watch out of the wait loop.
        '''
        self._should_stop = True
        self.stop_inotifier()

    def reload_handler(self, signum, frame):
        '''
        SIGTERM handler. Sets the should reload flag and stops the inotifier
        which brings the inotify watch out of the wait loop.
        '''
        self._should_reload = True
        self.stop_inotifier()

    def siginstall(self):
        self.sigset = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        signal.signal(signal.SIGINT, self.term_handler)
        signal.signal(signal.SIGTERM, self.term_handler)
        signal.signal(signal.SIGHUP, self.reload_handler)

    def sigblock(self):
        '''
        Blocks the relevant signals during mail processing. After each
        processed mail sigpending() is checked to handle the signals
        gracefully without too much delay.
        '''
        signal.pthread_sigmask(signal.SIG_BLOCK, self.sigset)

    def sigunblock(self):
        '''
        Unblock the signals again
        '''
        signal.pthread_sigmask(signal.SIG_UNBLOCK, self.sigset)

    # The remail internal queueing
    def queue_newmail(self, path):
        '''
        new mail queue. Contains mails which have not been processed.
        Scanned from the 'new' folder in the maildir after setting
        up the async inotifier to make sure that existing entries are
        collected. When the inotify based processing runs new entries
        are added when inotify.process_events() is invoked.

        Duplicate entries are prevented. Also mails in failedmails
        are ignored.
        '''
        if path not in self.failedmails and path not in self.newmails:
            self.newmails.append(path)

    def scan_maildir(self):
        '''
        Scan all existing mails in maildir/new and maildir/cur (not
        in use yet). The scanning happens after the inotifier was
        installed and before the inotify events are processed. Duplicate
        entries are prevented in the enqeueing function
        '''
        mdir = pathlib.Path(self.config.maildir) / 'cur'
        for p in mdir.iterdir():
            self.queue_newmail(str(p.resolve()))
        mdir = pathlib.Path(self.config.maildir) / 'new'
        for p in mdir.iterdir():
            self.queue_newmail(str(p.resolve()))

    # Inotify related functions
    def install_inotifier(self):
        '''
        Install an async inotifier on maildir/new to avoid polling
        the maildir.
        '''
        wm = pyinotify.WatchManager()
        self.inotifier = pyinotify.AsyncNotifier(wm, EventHandler(self))
        ndir = pathlib.Path(self.config.maildir) / 'new'
        wm.add_watch(str(ndir.resolve()), pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO)

    def stop_inotifier(self):
        '''
        Stop the inotifier. Called from signal handlers to stop waiting
        and processing either for termination or reconfiguration.
        '''
        if self.inotifier:
            self.inotifier.stop()
            self.inotifier = None

    def process_events(self):
        try:
            # Can't disable signals here as this can block
            if self.inotifier.check_events():
                self.inotifier.read_events();

            self.inotifier.process_events()

        except AttributeError as ex:
            # Handle the case gracefully where the inotifier died
            # There is surely a better way to do that :)
            txt = '%s' %ex
            if txt.find('check_events') > 0:
                pass
            elif txt.find('read_events') > 0:
                pass
            elif txt.find('process_events') > 0:
                pass
            else:
                raise ex

    def move_frozen(self, mailfile):
        try:
            txt = 'Failed to process mail file %s\n' %(mailfile)
            self.logger.log_warn(txt)
            fname = os.path.basename(mailfile)
            fpath = os.path.join(self.config.mailfrozen, 'new')
            fpath = os.path.join(fpath, fname)
            if os.path.isfile(mailfile):
                os.link(mailfile, fpath)
                os.unlink(mailfile)
                txt += 'Moved to %s\n' %fpath
                self.logger.log_warn(txt)
        except:
            pass

    def process_msg(self, msg):
        # Check whether one of the lists will take it
        for ml in self.mailinglists:
            if not ml.enabled:
                continue
            dest = ml.get_destination(msg)
            if not dest:
                continue
            try:
                if ml.process_mail(msg, dest):
                    return 0
                return 2
            except Exception as ex:
                txt = 'Failed to process mail file %s\n' %(mailfile)
                self.logger.log_exception(txt, ex)
                break
        return 1

    # The actual mail processing
    def process_mail(self, queue):
        '''
        Process the mails which are enqueued on the internal list. Invoked
        with signals disabled. After each processed mail the signals are
        checked.
        '''
        while len(queue) and not self._should_stop and not signal.sigpending():
            mailfile = queue.pop()

            # Try to read the mail
            try:
                msg = message_from_binary_file(open(mailfile, 'rb'),
                                               policy=self.policy)
            except Exception as ex:
                self.move_frozen(mailfile)
                continue

            res = self.process_msg(msg)

            if res == 0:
                os.unlink(mailfile)
            else:
                self.move_frozen(mailfile)

    def process_mails(self):
        '''
        Block signals for mail processing to simplify the mail processing
        as some of the invoked functions are not restarting their syscalls.
        Blocking the syscalls avoids dealing with those exceptions all over
        the place. The mail processing checks for pending signals after each
        mail so the delay for handling them is minimal.
        '''
        self.sigblock()
        self.process_mail(self.newmails)
        self.sigunblock()

    # Configuration processing
    def config_list(self, ml):
        '''
        Configure a mailing list from the list config file
        '''
        try:
            cfgdict = self.yaml.load(open(ml.listcfg))
        except Exception as ex:
            txt = 'Failed to load list configfile %s' %ml.listcfg
            self.logger.log_exception(txt, ex)
            txt = 'Disabling list. Waiting for reconfiguration'
            self.logger.log_warn(txt)
            ml.enabled = False

        # If the list is disabled, nothing else to do than wait
        if not ml.enabled:
            return

        try:
            subscr = cfgdict.get('subscribers', {})
            ml.config_subscribers(subscr)
        except RemailConfigException as ex:
            txt = 'list %s disabled. Waiting for reconfiguration' % ml.name
            self.logger.log_exception(txt, ex)
            self.log_warn(txt)
            ml.enabled = False

    def read_config(self):
        '''
        Read the main configuration file and analyze it.
        '''
        try:
            cfgdict = self.yaml.load(open(self.cfgfile))
        except Exception as ex:
            txt = 'Failed to load configfile %s.' %self.cfgfile
            self.logger.log_exception(txt, ex)
            txt = 'Waiting for reconfiguration'
            self.logger.log_warn(txt)
            cfgdict = {}


        # If remail is disabled, nothing else to do than wait
        self.enabled = cfgdict.get('enabled', False)
        if not self.enabled:
            return

        # Read the configuration
        try:
            self.config = main_config(cfgdict)
        except RemailConfigException as ex:
            txt = 'remail disabled. Waiting for reconfiguration'
            self.logger.log_exception(txt, ex)
            self.enabled = False

        # If remail is disabled, nothing else to do than wait
        if not self.enabled:
            return

        # Read the mailing list subscribers
        for l in self.config.lists:
            self.config_list(l)

        # Now set up the real mailing lists
        self.mailinglists = []
        for l in self.config.lists:
            ml = maillist(l, self.logger, self.config.use_smtp)
            self.mailinglists.append(ml)

    def show_config(self):
        '''
        Show the configuration of this remail instance including
        the mailing list configurations on stdout.
        '''
        self.read_config()
        if not self.enabled:
            print('Disabled')
            return

        self.config.show()

    def check_keys(self):
        self.read_config()
        if not self.enabled:
            return
        for ml in self.mailinglists:
            ml.check_keys()

    def reconfigure(self):
        """
        Check for reconfiguration request.
        """
        if not self._should_reload:
            return
        self._should_reload = False

        # Prevent concurrent updates from a notification
        # mechanism or a cronjob.
        fd = open('lock', 'w')
        fcntl.flock(fd, fcntl.LOCK_EX)

        self.read_config()

        if not self.enabled:
            return

        for ml in self.mailinglists:
            try:
                ml.start_list()
            except Exception as ex:
                txt = 'Failed to start list %s' % (ml.get_name())
                self.logger.log_exception(txt, ex)
                ml.enabled = False

        fcntl.flock(fd, fcntl.LOCK_UN)

    def should_stop(self):
        return self._should_stop

    def check_config(self):
        # Invoke reconfiguration if requested
        self.reconfigure()

        # Wait if configuration is disabled
        while not self.enabled and not self.should_stop():
            signal.pause()
            if not self.should_stop():
                self.reconfigure()

        return self.should_stop()

    # The pipe handling interface
    def handle_pipe(self):
        self._should_reload = True
        self.reconfigure()

        if not self.enabled:
            return 1

        policy = EmailPolicy(utf8=True)
        msg = message_from_file(sys.stdin, policy=policy)
        return self.process_msg(msg)

    # The runner
    def run(self):

        # Force configuration reload
        self._should_reload = True

        while not self.should_stop():

            # Check configuration request and eventually wait if disabled
            if self.check_config():
                continue

            # Install inotify watch on the maildir
            self.install_inotifier()
            # Scan for existing mail
            self.scan_maildir()
            self.process_mails()

            while not self._should_stop and not self._should_reload:
                try:
                    self.process_events()
                    self.process_mails()
                except Exception as ex:
                    self.stop_inotifier()
                    self.logger.log_exception('', ex)
                    self._should_stop = True
