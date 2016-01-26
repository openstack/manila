#!/usr/bin/env python

# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Interactive shell based on Django:
#
# Copyright (c) 2005, the Lawrence Journal-World
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
#     3. Neither the name of Django nor the names of its contributors may be
#        used to endorse or promote products derived from this software without
#        specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""
  CLI interface for manila management.
"""

from __future__ import print_function

import os
import sys

from manila import i18n
i18n.enable_lazy()

from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from manila.common import config  # Need to register global_opts  # noqa
from manila import context
from manila import db
from manila.db import migration
from manila.i18n import _
from manila import utils
from manila import version

CONF = cfg.CONF


# Decorators for actions
def args(*args, **kwargs):
    def _decorator(func):
        func.__dict__.setdefault('args', []).insert(0, (args, kwargs))
        return func
    return _decorator


def param2id(object_id):
    """Helper function to convert various id types to internal id.

    args: [object_id], e.g. 'vol-0000000a' or 'volume-0000000a' or '10'
    """
    if uuidutils.is_uuid_like(object_id):
        return object_id
    elif '-' in object_id:
        # FIXME(ja): mapping occurs in nova?
        pass
    else:
        return int(object_id)


class ShellCommands(object):
    def bpython(self):
        """Runs a bpython shell.

        Falls back to Ipython/python shell if unavailable
        """
        self.run('bpython')

    def ipython(self):
        """Runs an Ipython shell.

        Falls back to Python shell if unavailable
        """
        self.run('ipython')

    def python(self):
        """Runs a python shell.

        Falls back to Python shell if unavailable
        """
        self.run('python')

    @args('--shell', dest="shell",
          metavar='<bpython|ipython|python>',
          help='Python shell')
    def run(self, shell=None):
        """Runs a Python interactive interpreter."""
        if not shell:
            shell = 'bpython'

        if shell == 'bpython':
            try:
                import bpython
                bpython.embed()
            except ImportError:
                shell = 'ipython'
        if shell == 'ipython':
            try:
                from IPython import embed
                embed()
            except ImportError:
                # Ipython < 0.11
                try:
                    import IPython

                    # Explicitly pass an empty list as arguments, because
                    # otherwise IPython would use sys.argv from this script.
                    shell = IPython.Shell.IPShell(argv=[])
                    shell.mainloop()
                except ImportError:
                    # no IPython module
                    shell = 'python'

        if shell == 'python':
            import code
            try:
                # Try activating rlcompleter, because it's handy.
                import readline
            except ImportError:
                pass
            else:
                # We don't have to wrap the following import in a 'try',
                # because we already know 'readline' was imported successfully.
                import rlcompleter  # noqa
                readline.parse_and_bind("tab:complete")
            code.interact()

    @args('--path', required=True, help='Script path')
    def script(self, path):
        """Runs the script from the specifed path with flags set properly.

        arguments: path
        """
        exec(compile(open(path).read(), path, 'exec'), locals(), globals())


class HostCommands(object):
    """List hosts."""

    @args('zone', nargs='?', default=None,
          help='Availability Zone (default: %(default)s)')
    def list(self, zone=None):
        """Show a list of all physical hosts. Filter by zone.

        args: [zone]
        """
        print("%-25s\t%-15s" % (_('host'), _('zone')))
        ctxt = context.get_admin_context()
        services = db.service_get_all(ctxt)
        if zone:
            services = [
                s for s in services if s['availability_zone']['name'] == zone]
        hosts = []
        for srv in services:
            if not [h for h in hosts if h['host'] == srv['host']]:
                hosts.append(srv)

        for h in hosts:
            print("%-25s\t%-15s" % (h['host'], h['availability_zone']['name']))


class DbCommands(object):
    """Class for managing the database."""

    def __init__(self):
        pass

    @args('version', nargs='?', default=None,
          help='Database version')
    def sync(self, version=None):
        """Sync the database up to the most recent version."""
        return migration.upgrade(version)

    def version(self):
        """Print the current database version."""
        print(migration.version())

    # NOTE(imalinovskiy):
    # Manila init migration hardcoded here,
    # because alembic has strange behaviour:
    # downgrade base = downgrade from head(162a3e673105) -> base(162a3e673105)
    #                = downgrade from 162a3e673105 -> (empty) [ERROR]
    # downgrade 162a3e673105 = downgrade from head(162a3e673105)->162a3e673105
    #                        = do nothing [OK]
    @args('version', nargs='?', default='162a3e673105',
          help='Version to downgrade')
    def downgrade(self, version=None):
        """Downgrade database to the given version."""
        return migration.downgrade(version)

    @args('--message', help='Revision message')
    @args('--autogenerate', help='Autogenerate migration from schema')
    def revision(self, message, autogenerate):
        """Generate new migration."""
        return migration.revision(message, autogenerate)

    @args('version', nargs='?', default=None,
          help='Version to stamp version table with')
    def stamp(self, version=None):
        """Stamp the version table with the given version."""
        return migration.stamp(version)


class VersionCommands(object):
    """Class for exposing the codebase version."""

    def list(self):
        print(version.version_string())

    def __call__(self):
        self.list()


class ConfigCommands(object):
    """Class for exposing the flags defined by flag_file(s)."""

    def list(self):
        for key, value in CONF.items():
            if value is not None:
                print('%s = %s' % (key, value))


class GetLogCommands(object):
    """Get logging information."""

    def errors(self):
        """Get all of the errors from the log files."""
        error_found = 0
        if CONF.log_dir:
            logs = [x for x in os.listdir(CONF.log_dir) if x.endswith('.log')]
            for file in logs:
                log_file = os.path.join(CONF.log_dir, file)
                lines = [line.strip() for line in open(log_file, "r")]
                lines.reverse()
                print_name = 0
                for index, line in enumerate(lines):
                    if line.find(" ERROR ") > 0:
                        error_found += 1
                        if print_name == 0:
                            print(log_file + ":-")
                            print_name = 1
                        print("Line %d : %s" % (len(lines) - index, line))
        if error_found == 0:
            print("No errors in logfiles!")

    @args('num_entries', nargs='?', type=int, default=10,
          help='Number of entries to list (default: %(default)d)')
    def syslog(self, num_entries=10):
        """Get <num_entries> of the manila syslog events."""
        entries = int(num_entries)
        count = 0
        log_file = ''
        if os.path.exists('/var/log/syslog'):
            log_file = '/var/log/syslog'
        elif os.path.exists('/var/log/messages'):
            log_file = '/var/log/messages'
        else:
            print("Unable to find system log file!")
            sys.exit(1)
        lines = [line.strip() for line in open(log_file, "r")]
        lines.reverse()
        print("Last %s manila syslog entries:-" % (entries))
        for line in lines:
            if line.find("manila") > 0:
                count += 1
                print("%s" % (line))
            if count == entries:
                break

        if count == 0:
            print("No manila entries in syslog!")


class ServiceCommands(object):
    """Methods for managing services."""
    def list(self):
        """Show a list of all manila services."""
        ctxt = context.get_admin_context()
        services = db.service_get_all(ctxt)
        print_format = "%-16s %-36s %-16s %-10s %-5s %-10s"
        print(print_format % (
            _('Binary'),
            _('Host'),
            _('Zone'),
            _('Status'),
            _('State'),
            _('Updated At'))
        )
        for svc in services:
            alive = utils.service_is_up(svc)
            art = ":-)" if alive else "XXX"
            status = 'enabled'
            if svc['disabled']:
                status = 'disabled'
            print(print_format % (
                svc['binary'],
                svc['host'].partition('.')[0],
                svc['availability_zone']['name'],
                status,
                art,
                svc['updated_at'],
            ))


CATEGORIES = {
    'config': ConfigCommands,
    'db': DbCommands,
    'host': HostCommands,
    'logs': GetLogCommands,
    'service': ServiceCommands,
    'shell': ShellCommands,
    'version': VersionCommands
}


def methods_of(obj):
    """Get all callable methods of an object that don't start with underscore.

    Returns a list of tuples of the form (method_name, method).
    """
    result = []
    for i in dir(obj):
        if callable(getattr(obj, i)) and not i.startswith('_'):
            result.append((i, getattr(obj, i)))
    return result


def add_command_parsers(subparsers):
    for category in CATEGORIES:
        command_object = CATEGORIES[category]()

        parser = subparsers.add_parser(category)
        parser.set_defaults(command_object=command_object)

        category_subparsers = parser.add_subparsers(dest='action')

        for (action, action_fn) in methods_of(command_object):
            parser = category_subparsers.add_parser(action)

            action_kwargs = []
            for args, kwargs in getattr(action_fn, 'args', []):
                parser.add_argument(*args, **kwargs)

            parser.set_defaults(action_fn=action_fn)
            parser.set_defaults(action_kwargs=action_kwargs)


category_opt = cfg.SubCommandOpt('category',
                                 title='Command categories',
                                 handler=add_command_parsers)


def get_arg_string(args):
    arg = None
    if args[0] == '-':
        # (Note)zhiteng: args starts with CONF.oparser.prefix_chars
        # is optional args. Notice that cfg module takes care of
        # actual ArgParser so prefix_chars is always '-'.
        if args[1] == '-':
            # This is long optional arg
            arg = args[2:]
        else:
            arg = args[1:]
    else:
        arg = args

    return arg


def fetch_func_args(func):
    fn_args = []
    for args, kwargs in getattr(func, 'args', []):
        arg = get_arg_string(args[0])
        fn_args.append(getattr(CONF.category, arg))

    return fn_args


def main():
    """Parse options and call the appropriate class/method."""
    CONF.register_cli_opt(category_opt)
    script_name = sys.argv[0]
    if len(sys.argv) < 2:
        print(_("\nOpenStack manila version: %(version)s\n") %
              {'version': version.version_string()})
        print(script_name + " category action [<args>]")
        print(_("Available categories:"))
        for category in CATEGORIES:
            print("\t%s" % category)
        sys.exit(2)

    try:
        log.register_options(CONF)
        CONF(sys.argv[1:], project='manila',
             version=version.version_string())
        log.setup(CONF, "manila")
    except cfg.ConfigFilesNotFoundError:
        cfgfile = CONF.config_file[-1] if CONF.config_file else None
        if cfgfile and not os.access(cfgfile, os.R_OK):
            st = os.stat(cfgfile)
            print(_("Could not read %s. Re-running with sudo") % cfgfile)
            try:
                os.execvp('sudo', ['sudo', '-u', '#%s' % st.st_uid] + sys.argv)
            except Exception:
                print(_('sudo failed, continuing as if nothing happened'))

        print(_('Please re-run manila-manage as root.'))
        sys.exit(2)

    fn = CONF.category.action_fn

    fn_args = fetch_func_args(fn)
    fn(*fn_args)


if __name__ == '__main__':
    main()
