# clifr plugin for sos report: adds a bundle of the clifrd recording (recent
# history of processes, sockets, open files and system counters) to the
# report. Install it beside sos's own plugins (sos/report/plugins/clifr.py).
#
#   sos report -o clifr                              the last 6 hours
#   sos report -o clifr -k clifr.window=24h
#   sos report -o clifr -k clifr.start="2026-10-20 12:00" -k clifr.end="2026-10-20 13:00"
#   sos report -o clifr -k clifr.window=all          the whole recording
#
# The bundle is sos_commands/clifr/clifr-bundle.tar; read it with
# clifr --data-dir clifr-bundle.tar --at TIME "ps aux". It holds every
# process's command line (clifrd --redact masks secrets as they are recorded).

import shlex

from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt


class Clifr(Plugin, IndependentPlugin):

    short_desc = 'clifr flight recorder: recent history of processes and sockets'
    plugin_name = 'clifr'
    profiles = ('system',)
    commands = ('clifrd',)
    files = ('/var/lib/clifr',)

    option_list = [
        PluginOpt('window', default='6h', val_type=str,
                  desc='how far back to bundle (e.g. 6h, 2d), or "all"'),
        # Not "since": sos's own --since would shadow it.
        PluginOpt('start', default='', val_type=str,
                  desc='start of the window (local time, e.g. "2026-10-20 12:00"); '
                       'overrides window'),
        PluginOpt('end', default='', val_type=str,
                  desc='end of the window (default: now); with start'),
        PluginOpt('datadir', default='/var/lib/clifr', val_type=str,
                  desc='clifrd data directory'),
        PluginOpt('clifrd', default='clifrd', val_type=str,
                  desc='the clifrd command, a full path if it is not in /usr/bin or /usr/sbin'),
    ]

    def setup(self):
        self.add_copy_spec('/etc/clifr')
        clifrd = shlex.quote(self.get_option('clifrd'))
        self.add_cmd_output([f'{clifrd} --version', f'{clifrd} doctor'])

        datadir = self.get_option('datadir')
        if not self.path_exists(datadir):
            self._log_info(f'no clifrd data directory at {datadir}')
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
