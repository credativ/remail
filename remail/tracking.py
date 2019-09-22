#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright Thomas Gleixner <tglx@linutronix.de>
#
# Account state tracking

from ruamel.yaml import YAML

class RemailTrackerException(Exception):
    pass

class account_tracking(object):
    '''Subscriber account tracking in a yaml file which is not part of the
    configuration as the configuration is git based and updates to it
    cannot be pushed back into the repository without creating a major
    trainwreck.

    The local states are: 'DISABLED', 'REGISTERED', 'FROZEN', 'ENABLED'

    The FROZEN state is set by bounce processing and can only be removed by
    two consecutive configuration updates (disable/enable) for now.  Not
    the most pretty mechanism, but everything else turned out to be even
    more horrible.
    '''
    def __init__(self, trcfg, logger):
        self.logger = logger
        self.config = trcfg
        self.yaml = YAML()
        try:
            self.tracked = self.yaml.load(open(self.config.tracking_file))
        except:
            self.tracked = {}

    def tracking_init(self, subscribers):
        '''
        Initialize the state tracker and safe current state
        after consolidating it with the configuration file

        Returns a lost of accounts which require to be sent a
        welcome mail.
        '''
        welcome = []
        for acc in subscribers.values():
            # Check if the account is tracked already
            if acc.addr in self.tracked:
                # Check the state for consistency
                state = self.tracked[acc.addr]

                # Last state was disabled.
                if state == 'DISABLED':
                    # If enabled in the config file set the state to
                    # registered
                    if acc.enabled:
                        state = 'REGISTERED'
                        welcome.append(acc)

                # Last state was frozen (Bounce processing...)
                elif state == 'FROZEN':
                    # If it's disabled in the config, remove the frozen
                    # state. Otherwise disable the account in the in memory
                    # configuration until it is really disabled in the real
                    # configuration file. See above.
                    if not acc.enabled:
                        state = 'DISABLED'
                    else:
                        acc.enabled = False
                        txt = 'Account %s frozen by tracking' % acc.addr
                        self.logger.log_warn(txt)

                # Last state was enabled or registered
                elif state == 'ENABLED' or state == 'REGISTERED':
                    if not acc.enabled:
                        state = 'DISABLED'
                    elif state == 'REGISTERED':
                        welcome.append(acc)

                # Ooops.  Should not happen!
                else:
                    if not acc.enabled:
                        state = 'DISABLED'
                    else:
                        state = 'REGISTERED'
                        welcome.append(acc)
                    pass

            # Untracked account
            else:
                if not acc.enabled:
                    state = 'DISABLED'
                else:
                    state = 'REGISTERED'
                    welcome.append(acc)

            # Update the tracking dict
            self.tracked[acc.addr] = state

        # Remove all accounts from the tracker which are not longer
        # in the subscriber list
        for addr in list(self.tracked):
            if addr not in subscribers.keys():
                del self.tracked[addr]

        # Update the tracking file
        self.dump_tracker()
        return welcome

    def dump_tracker(self):
        try:
            self.yaml.dump(self.tracked, open(self.config.tracking_file, 'w'))
        except Exception as ex:
            txt = 'Failed to dump to %s: %s' %(self.config.tracking_file, ex)
            raise RemailTrackerException(txt)

    def freeze_account(self, acc):
        self.tracked[acc.addr] = 'FROZEN'
        self.dump_tracker()

    def enable_account(self, acc):
        self.tracked[acc.addr] = 'ENABLED'
        self.dump_tracker()

    def get_state(self, acc):
        return self.tracked[acc.addr]
