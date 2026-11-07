# Copyright (C) 2026 Jorge L. Rueda B. <jlrueda@gmail.com>

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Unlike the rest of clifr (AGPL-3.0-only), this plugin is GPL-2.0-only, as
# sos is: it runs inside sos (see clifr's LICENSING.md). Install it beside
# sos's own plugins (sos/report/plugins/clifr.py).

import shlex

from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt


class Clifr(Plugin, IndependentPlugin):
    """
    clifr is a flight recorder for Linux: its recorder, clifrd, keeps a
    record of which processes ran (even short-lived ones), which TCP
    connections and open files each one had, and the system's counters.
    This plugin adds a bundle of that recording to the report, so the
    state of the system can be examined at the time of a problem rather
    than at the time the report was taken. It also collects clifrd's
    configuration (/etc/clifr) and the output of 'clifrd doctor'.

    The bundle is sos_commands/clifr/clifr-bundle.tar. Read it with
    clifr --data-dir clifr-bundle.tar --at TIME "ps aux". It holds every
    process's command line (clifrd's redact patterns mask secrets as they
    are recorded).

    By default the bundle covers the last 6 hours; other windows:

        sos report -o clifr -k clifr.window=24h
        sos report -o clifr -k clifr.start="2026-10-20 12:00" \\
            -k clifr.end="2026-10-20 13:00"
        sos report -o clifr -k clifr.window=all

    With --clean (or --mask) the bundle is left out, as sos clean would
    remove it: it obfuscates text files, not the Parquet files in the
    bundle, which hold every host name, address and user name of the
    recording. With --keep-binary-files as well it is added, as it is
    (not obfuscated).
    """

    short_desc = ('clifr flight recorder: recent history of processes '
                  'and sockets')
    plugin_name = 'clifr'
    profiles = ('system',)
    commands = ('clifrd',)
    files = ('/var/lib/clifr',)

    option_list = [
        PluginOpt('window', default='6h', val_type=str,
                  desc='how far back to bundle (e.g. 6h, 2d), or "all"'),
        # Not "since": sos's own --since would shadow it.
        PluginOpt('start', default='', val_type=str,
                  desc='start of the window (local time, e.g. '
                       '"2026-10-20 12:00"); overrides window'),
        PluginOpt('end', default='', val_type=str,
                  desc='end of the window (default: now); with start'),
        PluginOpt('datadir', default='/var/lib/clifr', val_type=str,
                  desc='clifrd data directory'),
        PluginOpt('clifrd', default='clifrd', val_type=str,
                  desc='the clifrd command, a full path if it is not in '
                       '/usr/bin or /usr/sbin'),
    ]

    def setup(self):
        # The access tokens of clifrd --serve (only their hashes, but they
        # decide who reads every process's command line): never collected.
        self.add_forbidden_path([
            '/etc/clifr/serve-tokens',
            '/etc/clifr/serve-tokens.tmp',
        ])
        self.add_copy_spec('/etc/clifr')
        clifrd = shlex.quote(self.get_option('clifrd'))
        self.add_cmd_output([f'{clifrd} --version', f'{clifrd} doctor'])

        datadir = self.get_option('datadir')
        if not self.path_exists(datadir):
            self._log_info(f'no clifrd data directory at {datadir}')
            return
        opts = self.commons['cmdlineopts']
        if (getattr(opts, 'clean', False)
                and not getattr(opts, 'keep_binary_files', False)):
            note = ('The clifr bundle was left out: sos clean (--clean, '
                    '--mask) removes binary files, and cannot obfuscate the '
                    'host names, addresses and user names in its Parquet '
                    'files. --keep-binary-files adds it as it is; or send '
                    'it apart (clifrd bundle).\n')
            self._log_warn(note.strip())
            self.add_string_as_file(note, 'clifr-bundle-left-out.txt')
            return
        cmd = f"{clifrd} bundle --data-dir {shlex.quote(datadir)}"
        since, until = self.get_option('start'), self.get_option('end')
        window = str(self.get_option('window')).strip()
        if since or until:
            if since:
                cmd += f" --since {shlex.quote(since)}"
            if until:
                cmd += f" --until {shlex.quote(until)}"
        elif window.lower() not in ('all', '0', ''):
            cmd += f" --last {shlex.quote(window)}"
        path = self.get_cmd_output_path()
        cmd += f" -o {shlex.quote(path + '/clifr-bundle.tar')}"
        # The bundle is written by clifrd itself (its summary is the output).
        self.add_cmd_output(cmd, suggest_filename='clifrd_bundle', timeout=900,
                            chroot=self.tmp_in_sysroot())

# vim: set et ts=4 sw=4 :
