# Copyright (c) 2016, MapR Technologies
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
"""
Utility for processing MapR cluster operations
"""

import json
import pipes
import socket

from oslo_concurrency import processutils
from oslo_log import log
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila import utils

LOG = log.getLogger(__name__)


def get_version_handler(configuration):
    # here can be choosing DriverUtils depend on cluster version
    return BaseDriverUtil(configuration)


class BaseDriverUtil(object):
    """Utility class for MapR-FS specific operations."""
    NOT_FOUND_MSG = 'No such'
    ERROR_MSG = 'ERROR'

    def __init__(self, configuration):
        self.configuration = configuration
        self.ssh_connections = {}
        self.hosts = self.configuration.maprfs_clinode_ip
        self.local_hosts = socket.gethostbyname_ex(socket.gethostname())[2]
        self.maprcli_bin = '/usr/bin/maprcli'
        self.hadoop_bin = '/usr/bin/hadoop'

    def _execute(self, *cmd, **kwargs):
        for x in range(0, len(self.hosts)):
            try:
                check_exit_code = kwargs.pop('check_exit_code', True)
                host = self.hosts[x]
                if host in self.local_hosts:
                    cmd = self._as_user(cmd,
                                        self.configuration.maprfs_ssh_name)
                    out, err = utils.execute(*cmd,
                                             check_exit_code=check_exit_code)
                else:
                    out, err = self._run_ssh(host, cmd, check_exit_code)
                # move available cldb host to the beginning
                if x > 0:
                    self.hosts[0], self.hosts[x] = self.hosts[x], self.hosts[0]
                return out, err
            except exception.ProcessExecutionError as e:
                if self._check_error(e):
                    raise
                elif x < len(self.hosts) - 1:
                    msg = ('Error running SSH command. Trying another host')
                    LOG.error(msg)
                else:
                    raise
            except Exception as e:
                if x < len(self.hosts) - 1:
                    msg = ('Error running SSH command. Trying another host')
                    LOG.error(msg)
                else:
                    raise exception.ProcessExecutionError(six.text_type(e))

    def _run_ssh(self, host, cmd_list, check_exit_code=False):
        command = ' '.join(pipes.quote(cmd_arg) for cmd_arg in cmd_list)
        connection = self.ssh_connections.get(host)
        if connection is None:
            ssh_name = self.configuration.maprfs_ssh_name
            password = self.configuration.maprfs_ssh_pw
            private_key = self.configuration.maprfs_ssh_private_key
            remote_ssh_port = self.configuration.maprfs_ssh_port
            ssh_conn_timeout = self.configuration.ssh_conn_timeout
            min_size = self.configuration.ssh_min_pool_conn
            max_size = self.configuration.ssh_max_pool_conn

            ssh_pool = utils.SSHPool(host,
                                     remote_ssh_port,
                                     ssh_conn_timeout,
                                     ssh_name,
                                     password=password,
                                     privatekey=private_key,
                                     min_size=min_size,
                                     max_size=max_size)
            ssh = ssh_pool.create()
            self.ssh_connections[host] = (ssh_pool, ssh)
        else:
            ssh_pool, ssh = connection

        if not ssh.get_transport().is_active():
            ssh_pool.remove(ssh)
            ssh = ssh_pool.create()
            self.ssh_connections[host] = (ssh_pool, ssh)
        return processutils.ssh_execute(
            ssh,
            command,
            check_exit_code=check_exit_code)

    @staticmethod
    def _check_error(error):
        # check if error was native
        return BaseDriverUtil.ERROR_MSG in error.stdout

    @staticmethod
    def _as_user(cmd, user):
        return ['sudo', 'su', '-', user, '-c',
                ' '.join(pipes.quote(cmd_arg) for cmd_arg in cmd)]

    @staticmethod
    def _add_params(cmd, **kwargs):
        params = []
        for x in kwargs.keys():
            params.append('-' + x)
            params.append(kwargs[x])
        return cmd + params

    def create_volume(self, name, path, size, **kwargs):
        # delete size param as it is set separately
        if kwargs.get('quota'):
            del kwargs['quota']
        sizestr = six.text_type(size) + 'G'
        cmd = [self.maprcli_bin, 'volume', 'create', '-name',
               name, '-path', path, '-quota',
               sizestr, '-readAce', '', '-writeAce', '']
        cmd = self._add_params(cmd, **kwargs)
        self._execute(*cmd)

    def volume_exists(self, volume_name):
        cmd = [self.maprcli_bin, 'volume', 'info', '-name', volume_name]
        out, __ = self._execute(*cmd, check_exit_code=False)
        return self.NOT_FOUND_MSG not in out

    def delete_volume(self, name):
        cmd = [self.maprcli_bin, 'volume', 'remove', '-name', name, '-force',
               'true']
        out, __ = self._execute(*cmd, check_exit_code=False)
        # if volume does not exist do not raise exception.ProcessExecutionError
        if self.ERROR_MSG in out and self.NOT_FOUND_MSG not in out:
            raise exception.ProcessExecutionError(out)

    def set_volume_size(self, name, size):
        sizestr = six.text_type(size) + 'G'
        cmd = [self.maprcli_bin, 'volume', 'modify', '-name', name, '-quota',
               sizestr]
        self._execute(*cmd)

    def create_snapshot(self, name, volume_name):
        cmd = [self.maprcli_bin, 'volume', 'snapshot', 'create',
               '-snapshotname',
               name, '-volume', volume_name]
        self._execute(*cmd)

    def delete_snapshot(self, name, volume_name):
        cmd = [self.maprcli_bin, 'volume', 'snapshot', 'remove',
               '-snapshotname',
               name, '-volume', volume_name]
        out, __ = self._execute(*cmd, check_exit_code=False)
        # if snapshot does not exist do not raise ProcessExecutionError
        if self.ERROR_MSG in out and self.NOT_FOUND_MSG not in out:
            raise exception.ProcessExecutionError(out)

    def get_volume_info(self, volume_name, columns=None):
        cmd = [self.maprcli_bin, 'volume', 'info', '-name', volume_name,
               '-json']
        if columns:
            cmd += ['-columns', ','.join(columns)]
        out, __ = self._execute(*cmd)
        return json.loads(out)['data'][0]

    def get_volume_info_by_path(self, volume_path, columns=None,
                                check_if_exists=False):
        cmd = [self.maprcli_bin, 'volume', 'info', '-path', volume_path,
               '-json']
        if columns:
            cmd += ['-columns', ','.join(columns)]
        out, __ = self._execute(*cmd, check_exit_code=not check_if_exists)
        if check_if_exists and self.NOT_FOUND_MSG in out:
            return None
        return json.loads(out)['data'][0]

    def get_snapshot_list(self, volume_name=None, volume_path=None):
        params = {}
        if volume_name:
            params['volume'] = volume_name
        if volume_path:
            params['path'] = volume_name
        cmd = [self.maprcli_bin, 'volume', 'snapshot', 'list', '-volume',
               '-columns',
               'snapshotname', '-json']
        cmd = self._add_params(cmd, **params)
        out, __ = self._execute(*cmd)
        return [x['snapshotname'] for x in json.loads(out)['data']]

    def rename_volume(self, name, new_name):
        cmd = [self.maprcli_bin, 'volume', 'rename', '-name', name, '-newname',
               new_name]
        self._execute(*cmd)

    def fs_capacity(self):
        cmd = [self.hadoop_bin, 'fs', '-df']
        out, err = self._execute(*cmd)
        lines = out.splitlines()
        try:
            fields = lines[1].split()
            total = int(fields[1])
            free = int(fields[3])
        except (IndexError, ValueError):
            msg = _('Failed to get MapR-FS capacity info.')
            LOG.exception(msg)
            raise exception.ProcessExecutionError(msg)
        return total, free

    def maprfs_ls(self, path):
        cmd = [self.hadoop_bin, 'fs', '-ls', path]
        out, __ = self._execute(*cmd)
        return out

    def maprfs_cp(self, source, dest):
        cmd = [self.hadoop_bin, 'fs', '-cp', '-p', source, dest]
        self._execute(*cmd)

    def maprfs_chmod(self, dest, mod):
        cmd = [self.hadoop_bin, 'fs', '-chmod', mod, dest]
        self._execute(*cmd)

    def maprfs_du(self, path):
        cmd = [self.hadoop_bin, 'fs', '-du', '-s', path]
        out, __ = self._execute(*cmd)
        return int(out.split(' ')[0])

    def check_state(self):
        cmd = [self.hadoop_bin, 'fs', '-ls', '/']
        out, __ = self._execute(*cmd, check_exit_code=False)
        return 'Found' in out

    def dir_not_empty(self, path):
        cmd = [self.hadoop_bin, 'fs', '-ls', path]
        out, __ = self._execute(*cmd, check_exit_code=False)
        return 'Found' in out

    def set_volume_ace(self, volume_name, access_rules):
        read_accesses = []
        write_accesses = []
        for access_rule in access_rules:
            if access_rule['access_level'] == constants.ACCESS_LEVEL_RO:
                read_accesses.append(access_rule['access_to'])
            elif access_rule['access_level'] == constants.ACCESS_LEVEL_RW:
                read_accesses.append(access_rule['access_to'])
                write_accesses.append(access_rule['access_to'])

        def rule_type(access_to):
            if self.group_exists(access_to):
                return 'g'
            elif self.user_exists(access_to):
                return 'u'
            else:
                # if nor user nor group exits, it should try add group rule
                return 'g'

        read_accesses_string = '|'.join(
            map(lambda x: rule_type(x) + ':' + x, read_accesses))
        write_accesses_string = '|'.join(
            map(lambda x: rule_type(x) + ':' + x, write_accesses))
        cmd = [self.maprcli_bin, 'volume', 'modify', '-name', volume_name,
               '-readAce', read_accesses_string, '-writeAce',
               write_accesses_string]
        self._execute(*cmd)

    def add_volume_ace_rules(self, volume_name, access_rules):
        if not access_rules:
            return
        access_rules_map = self.get_access_rules(volume_name)
        for access_rule in access_rules:
            access_rules_map[access_rule['access_to']] = access_rule
        self.set_volume_ace(volume_name, access_rules_map.values())

    def remove_volume_ace_rules(self, volume_name, access_rules):
        if not access_rules:
            return
        access_rules_map = self.get_access_rules(volume_name)
        for access_rule in access_rules:
            if access_rules_map.get(access_rule['access_to']):
                del access_rules_map[access_rule['access_to']]
        self.set_volume_ace(volume_name, access_rules_map.values())

    def get_access_rules(self, volume_name):
        info = self.get_volume_info(volume_name)
        aces = info['volumeAces']
        read_ace = aces['readAce']
        write_ace = aces['writeAce']
        access_rules_map = {}
        self._retrieve_access_rules_from_ace(read_ace, 'r', access_rules_map)
        self._retrieve_access_rules_from_ace(write_ace, 'w', access_rules_map)
        return access_rules_map

    def _retrieve_access_rules_from_ace(self, ace, ace_type, access_rules_map):
        access = constants.ACCESS_LEVEL_RW if ace_type == 'w' else (
            constants.ACCESS_LEVEL_RO)
        if ace not in ['p', '']:
            write_rules = [x.strip() for x in ace.split('|')]
            for user in write_rules:
                rule_type, username = user.split(':')
                if rule_type not in ['u', 'g']:
                    continue
                access_rules_map[username] = {
                    'access_level': access,
                    'access_to': username,
                    'access_type': 'user',
                }

    def user_exists(self, user):
        cmd = ['getent', 'passwd', user]
        out, __ = self._execute(*cmd, check_exit_code=False)
        return out != ''

    def group_exists(self, group):
        cmd = ['getent', 'group', group]
        out, __ = self._execute(*cmd, check_exit_code=False)
        return out != ''

    def get_cluster_name(self):
        cmd = [self.maprcli_bin, 'dashboard', 'info', '-json']
        out, __ = self._execute(*cmd)
        try:
            return json.loads(out)['data'][0]['cluster']['name']
        except (IndexError, ValueError) as e:
            msg = (_("Failed to parse cluster name. Error: %s") % e)
            raise exception.ProcessExecutionError(msg)
