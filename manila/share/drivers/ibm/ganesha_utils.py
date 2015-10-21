# Copyright 2014 IBM Corp.
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
"""
Ganesha Admin Utilities

Ganesha NFS does not provide many tools for automating the process of creating
and managing export defintions.  This module provides utilities to help parse
a specified ganesha config file and return a map containing the export
definitions and attributes.  A method republishing updated export definitions
is also provided.  And there are methods for requesting the ganesha server
to reload the export definitions.

Consider moving this to common location for use by other manila drivers.
"""

import copy
import re
import socket
import time

import netaddr
from oslo_log import log
import six

from manila import exception
from manila.i18n import _, _LI
from manila import utils

LOG = log.getLogger(__name__)
# more simple pattern for matching a single avpair per line,
# skips lines starting with # comment char
AVPATTERN = re.compile('^\s*(?!#)\s*(?P<attr>\S+)\s*=\s*(?P<val>\S+)\s*;')

# NFS Ganesha v1.5, v2.0 format used here.
# TODO(nileshb): Upgrade it to NFS Ganesha 2.1 format.
DEFAULT_EXPORT_ATTRS = {
    'export_id': 'undefined',
    'path': 'undefined',
    'fsal': 'undefined',
    'root_access': '"*"',
    'rw_access': '"*"',
    'pseudo': 'undefined',
    'anonymous_root_uid': '-2',
    'nfs_protocols': '"3,4"',
    'transport_protocols': '"UDP,TCP"',
    'sectype': '"sys"',
    'maxread': '65536',
    'maxwrite': '65536',
    'prefread': '65536',
    'prefwrite': '65536',
    'filesystem_id': '192.168',
    'tag': 'undefined',
}

STARTING_EXPORT_ID = 100


def valid_flags():
    return DEFAULT_EXPORT_ATTRS.keys()


def parse_ganesha_config(configpath):
    """Parse the specified ganesha configuration.

    Parse a configuration file and return a list of lines that were found
    before the first EXPORT block, and a dictionary of exports and their
    attributes.

    The input configuration file should be a valid ganesha config file and the
    export blocks should be the last items in the file.
    :returns: pre_lines -- List of lines, before the exports clause begins
              exports -- Dict of exports, indexed with the 'export_id'

    Hers is a sample output:

    pre_lines =
    [   '###################################################',
        '#     Export entries',
        '###################################################',
        '',
        '',
        '# First export entry']

    exports =
    {   '100': {   'anonymous_root_uid': '-2',
                   'export_id': '100',
                   'filesystem_id': '192.168',
                   'fsal': '"GPFS"',
                   'maxread': '65536',
                   'maxwrite': '65536',
                   'nfs_protocols': '"3,4"',
                   'path': '"/gpfs0/share-0d7df0c0-4792-4e2a-68dc7206a164"',
                   'prefread': '65536',
                   'prefwrite': '65536',
                   'pseudo': '"/gpfs0/share-0d7df0c0-4792-4e2a-68dc7206a164"',
                   'root_access': '"*"',
                   'rw_access': '""',
                   'sectype': '"sys"',
                   'tag': '"fs100"',
                   'transport_protocols': '"UDP,TCP"'},
        '101': {   'anonymous_root_uid': '-2',
                   'export_id': '101',
                   'filesystem_id': '192.168',
                   'fsal': '"GPFS"',
                   'maxread': '65536',
                   'maxwrite': '65536',
                   'nfs_protocols': '"3,4"',
                   'path': '"/gpfs0/share-74bee4dc-e07a-44a9-4be619a13fb1"',
                   'prefread': '65536',
                   'prefwrite': '65536',
                   'pseudo': '"/gpfs0/share-74bee4dc-e07a-44a9-4be619a13fb1"',
                   'root_access': '"*"',
                   'rw_access': '"172.24.4.4"',
                   'sectype': '"sys"',
                   'tag': '"fs101"',
                   'transport_protocols': '"UDP,TCP"'}}
    """
    export_count = 0
    exports = dict()
    pre_lines = []
    with open(configpath) as f:
        for l in f.readlines():
            line = l.strip()
            if export_count == 0 and line != 'EXPORT':
                pre_lines.append(line)
            else:
                if line == 'EXPORT':
                    export_count += 1
                    expattrs = dict()
                try:
                    match_obj = AVPATTERN.match(line)
                    attr = match_obj.group('attr').lower()
                    val = match_obj.group('val')
                    expattrs[attr] = val
                    if attr == 'export_id':
                        exports[val] = expattrs
                except AttributeError:
                    pass

    if export_count != len(exports):
        msg = (_('Invalid export config file %(configpath)s: '
                 '%(exports)s export clauses found, but '
                 '%(export_ids)s export_ids.')
               % {"configpath": configpath,
                  "exports": str(export_count),
                  "export_ids": str(len(exports))})

        LOG.error(msg)
        raise exception.GPFSGaneshaException(msg)
    return pre_lines, exports


def _get_export_by_path(exports, path):
    for index, export in exports.items():
        if export and 'path' in export and export['path'].strip('"\'') == path:
            return export
    return None


def get_export_by_path(exports, path):
    """Return the export that matches the specified path."""
    return _get_export_by_path(exports, path)


def export_exists(exports, path):
    """Return true if an export exists with the specified path."""
    return _get_export_by_path(exports, path) is not None


def get_next_id(exports):
    """Return an export id that is one larger than largest existing id."""
    try:
        next_id = max(map(int, exports.keys())) + 1
    except ValueError:
        next_id = STARTING_EXPORT_ID

    LOG.debug("Export id = %d", next_id)
    return next_id


def get_export_template():
    return copy.copy(DEFAULT_EXPORT_ATTRS)


def _convert_ipstring_to_ipn(ipstring):
    """Transform a single ip string into a list of IPNetwork objects."""
    if netaddr.valid_glob(ipstring):
        ipns = netaddr.glob_to_cidrs(ipstring)
    else:
        try:
            ipns = [netaddr.IPNetwork(ipstring)]
        except netaddr.AddrFormatError:
            msg = (_('Invalid IP access string %s.') % ipstring)
            LOG.error(msg)
            raise exception.GPFSGaneshaException(msg)
    return ipns


def _format_ips(iptokens):
    ipaddrs = set()
    for iptoken in iptokens:
        ipn_list = _convert_ipstring_to_ipn(iptoken)
        for ipn in ipn_list:
            ips = [ip for ip in netaddr.iter_unique_ips(ipn)]
            ipaddrs = ipaddrs.union(ips)
    return ipaddrs


def format_access_list(access_string, deny_access=None):
    """Transform access string into a format ganesha understands."""
    # handle the case where there is an access string with a trailing comma
    access_string = access_string.strip(',')
    iptokens = access_string.split(',')

    ipaddrs = _format_ips(iptokens)

    if deny_access:
        deny_tokens = deny_access.split(',')
        deny_ipaddrs = _format_ips(deny_tokens)
        ipaddrs = ipaddrs - deny_ipaddrs

    ipaddrlist = sorted(list(ipaddrs))

    return ','.join([six.text_type(ip) for ip in ipaddrlist])


def _publish_local_config(configpath, pre_lines, exports):
    tmp_path = '%s.tmp.%s' % (configpath, time.time())
    LOG.debug("tmp_path = %s", tmp_path)
    cpcmd = ['install', '-m', '666', configpath, tmp_path]
    try:
        utils.execute(*cpcmd, run_as_root=True)
    except exception.ProcessExecutionError as e:
        msg = (_('Failed while publishing ganesha config locally. '
                 'Error: %s.') % six.text_type(e))
        LOG.error(msg)
        raise exception.GPFSGaneshaException(msg)

    with open(tmp_path, 'w+') as f:
        for l in pre_lines:
            f.write('%s\n' % l)
        for e in exports:
            f.write('EXPORT\n{\n')
            for attr in exports[e]:
                f.write('%s = %s ;\n' % (attr, exports[e][attr]))

            f.write('}\n')
    mvcmd = ['mv', tmp_path, configpath]
    try:
        utils.execute(*mvcmd, run_as_root=True)
    except exception.ProcessExecutionError as e:
        msg = (_('Failed while publishing ganesha config locally. '
                 'Error: %s.') % six.text_type(e))
        LOG.error(msg)
        raise exception.GPFSGaneshaException(msg)
    LOG.info(_LI('Ganesha config %s published locally.'), configpath)


def _publish_remote_config(server, sshlogin, sshkey, configpath):
    dest = '%s@%s:%s' % (sshlogin, server, configpath)
    scpcmd = ['scp', '-i', sshkey, configpath, dest]
    try:
        utils.execute(*scpcmd, run_as_root=False)
    except exception.ProcessExecutionError as e:
        msg = (_('Failed while publishing ganesha config on remote server. '
                 'Error: %s.') % six.text_type(e))
        LOG.error(msg)
        raise exception.GPFSGaneshaException(msg)
    LOG.info(_LI('Ganesha config %(path)s published to %(server)s.'),
             {'path': configpath,
              'server': server})


def publish_ganesha_config(servers, sshlogin, sshkey, configpath,
                           pre_lines, exports):
    """Publish the specified configuration information.

    Save the existing configuration file and then publish a new
    ganesha configuration to the specified path.  The pre-export
    lines are written first, followed by the collection of export
    definitions.
    """
    _publish_local_config(configpath, pre_lines, exports)

    localserver_iplist = socket.gethostbyname_ex(socket.gethostname())[2]
    for gsvr in servers:
        if gsvr not in localserver_iplist:
            _publish_remote_config(gsvr, sshlogin, sshkey, configpath)


def reload_ganesha_config(servers, sshlogin, service='ganesha.nfsd'):
    """Request ganesha server reload updated config."""

    # Note:  dynamic reload of ganesha config is not enabled
    # in ganesha v2.0. Therefore, the code uses the ganesha service restart
    # option to make sure the config changes are reloaded
    for server in servers:
        # Until reload is fully implemented and if the reload returns a bad
        # status revert to service restart instead
        LOG.info(_LI('Restart service %(service)s on %(server)s to force a '
                     'config file reload'),
                 {'service': service, 'server': server})
        run_local = True

        reload_cmd = ['service', service, 'restart']
        localserver_iplist = socket.gethostbyname_ex(
            socket.gethostname())[2]
        if server not in localserver_iplist:
            remote_login = sshlogin + '@' + server
            reload_cmd = ['ssh', remote_login] + reload_cmd
            run_local = False
        try:
            utils.execute(*reload_cmd, run_as_root=run_local)
        except exception.ProcessExecutionError as e:
            msg = (_('Could not restart service %(service)s on '
                     '%(server)s: %(excmsg)s')
                   % {'service': service,
                      'server': server,
                      'excmsg': six.text_type(e)})
            LOG.error(msg)
            raise exception.GPFSGaneshaException(msg)
