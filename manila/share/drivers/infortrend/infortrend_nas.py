# Copyright (c) 2019 Infortrend Technology, Inc.
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

import json
import re

from oslo_concurrency import processutils
from oslo_log import log
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import utils as share_utils
from manila import utils as manila_utils

LOG = log.getLogger(__name__)


def _bi_to_gi(bi_size):
    return bi_size / units.Gi


class InfortrendNAS(object):

    _SSH_PORT = 22

    def __init__(self, nas_ip, username, password, ssh_key,
                 timeout, pool_dict, channel_dict):
        self.nas_ip = nas_ip
        self.port = self._SSH_PORT
        self.username = username
        self.password = password
        self.ssh_key = ssh_key
        self.ssh_timeout = timeout
        self.pool_dict = pool_dict
        self.channel_dict = channel_dict
        self.command = ""
        self.ssh = None
        self.sshpool = None
        self.location = 'a@0'

    def _execute(self, command_line):
        command_line.extend(['-z', self.location])
        commands = ' '.join(command_line)
        manila_utils.check_ssh_injection(commands)
        LOG.debug('Executing: %(command)s', {'command': commands})

        cli_out = self._ssh_execute(commands)

        return self._parser(cli_out)

    def _ssh_execute(self, commands):
        try:
            out, err = processutils.ssh_execute(
                self.ssh, commands,
                timeout=self.ssh_timeout, check_exit_code=True)
        except processutils.ProcessExecutionError as pe:
            rc = pe.exit_code
            out = pe.stdout
            out = out.replace('\n', '\\n')
            msg = _('Error on execute ssh command. '
                    'Exit code: %(rc)d, msg: %(out)s') % {
                        'rc': rc, 'out': out}
            raise exception.InfortrendNASException(err=msg)

        return out

    def _parser(self, content=None):
        LOG.debug('parsing data:\n%s', content)
        content = content.replace("\r", "")
        content = content.strip()
        json_string = content.replace("'", "\"")
        cli_data = json_string.splitlines()[2]
        if cli_data:
            try:
                data_dict = json.loads(cli_data)
            except Exception:
                msg = _('Failed to parse data: '
                        '%(cli_data)s to dictionary.') % {
                            'cli_data': cli_data}
                LOG.error(msg)
                raise exception.InfortrendNASException(err=msg)

            rc = int(data_dict['cliCode'][0]['Return'], 16)
            if rc == 0:
                result = data_dict['data']
            else:
                result = data_dict['cliCode'][0]['CLI']
        else:
            msg = _('No data is returned from NAS.')
            LOG.error(msg)
            raise exception.InfortrendNASException(err=msg)

        if rc != 0:
            msg = _('NASCLI error, returned: %(result)s.') % {
                'result': result}
            LOG.error(msg)
            raise exception.InfortrendCLIException(
                err=msg, rc=rc, out=result)

        return rc, result

    def do_setup(self):
        self._init_connect()
        self._ensure_service_on('nfs')
        self._ensure_service_on('cifs')

    def _init_connect(self):
        if not (self.sshpool and self.ssh):
            self.sshpool = manila_utils.SSHPool(ip=self.nas_ip,
                                                port=self.port,
                                                conn_timeout=None,
                                                login=self.username,
                                                password=self.password,
                                                privatekey=self.ssh_key)
            self.ssh = self.sshpool.create()

        if not self.ssh.get_transport().is_active():
            self.sshpool = manila_utils.SSHPool(ip=self.nas_ip,
                                                port=self.port,
                                                conn_timeout=None,
                                                login=self.username,
                                                password=self.password,
                                                privatekey=self.ssh_key)
            self.ssh = self.sshpool.create()

        LOG.debug('NAScmd [%s@%s] start!', self.username, self.nas_ip)

    def check_for_setup_error(self):
        self._check_pools_setup()
        self._check_channels_status()

    def _ensure_service_on(self, proto, slot='A'):
        command_line = ['service', 'status', proto]
        rc, service_status = self._execute(command_line)
        if not service_status[0][slot][proto.upper()]['enabled']:
            command_line = ['service', 'restart', proto]
            self._execute(command_line)

    def _check_channels_status(self):
        channel_list = list(self.channel_dict.keys())
        command_line = ['ifconfig', 'inet', 'show']
        rc, channels_status = self._execute(command_line)
        for channel in channels_status:
            if 'CH' in channel['datalink']:
                ch = channel['datalink'].strip('CH')
                if ch in self.channel_dict.keys():
                    self.channel_dict[ch] = channel['IP']
                    channel_list.remove(ch)
                    if channel['status'] == 'DOWN':
                        LOG.warning('Channel [%(ch)s] status '
                                    'is down, please check.', {
                                        'ch': ch})
        if len(channel_list) != 0:
            msg = _('Channel setting %(channel_list)s is invalid!') % {
                'channel_list': channel_list}
            LOG.error(msg)
            raise exception.InfortrendNASException(message=msg)

    def _check_pools_setup(self):
        pool_list = list(self.pool_dict.keys())
        command_line = ['folder', 'status']
        rc, pool_data = self._execute(command_line)
        for pool in pool_data:
            pool_name = self._extract_pool_name(pool)
            if pool_name in self.pool_dict.keys():
                pool_list.remove(pool_name)
                self.pool_dict[pool_name]['id'] = pool['volumeId']
                self.pool_dict[pool_name]['path'] = pool['directory'] + '/'
            if len(pool_list) == 0:
                break

        if len(pool_list) != 0:
            msg = _('Please create %(pool_list)s pool/s in advance!') % {
                'pool_list': pool_list}
            LOG.error(msg)
            raise exception.InfortrendNASException(message=msg)

    def _extract_pool_name(self, pool_info):
        return pool_info['directory'].split('/')[1]

    def _extract_lv_name(self, pool_info):
        return pool_info['path'].split('/')[2]

    def update_pools_stats(self):
        pools = []
        command_line = ['folder', 'status']
        rc, pools_data = self._execute(command_line)

        for pool_info in pools_data:
            pool_name = self._extract_pool_name(pool_info)

            if pool_name in self.pool_dict.keys():
                total_space = float(pool_info['size'])
                pool_quota_used = self._get_pool_quota_used(pool_name)
                available_space = total_space - pool_quota_used

                total_capacity_gb = round(_bi_to_gi(total_space), 2)
                free_capacity_gb = round(_bi_to_gi(available_space), 2)

                pool = {
                    'pool_name': pool_name,
                    'total_capacity_gb': total_capacity_gb,
                    'free_capacity_gb': free_capacity_gb,
                    'reserved_percentage': 0,
                    'qos': False,
                    'dedupe': False,
                    'compression': False,
                    'snapshot_support': False,
                    'thin_provisioning': False,
                    'thick_provisioning': True,
                    'replication_type': None,
                }
                pools.append(pool)

        return pools

    def _get_pool_quota_used(self, pool_name):
        pool_quota_used = 0.0
        pool_data = self._get_share_pool_data(pool_name)
        folder_name = self._extract_lv_name(pool_data)

        command_line = ['fquota', 'status', pool_data['id'],
                        folder_name, '-t', 'folder']
        rc, quota_status = self._execute(command_line)

        for share_quota in quota_status:
            pool_quota_used += int(share_quota['quota'])

        return pool_quota_used

    def _get_share_pool_data(self, pool_name):
        if not pool_name:
            msg = _("Pool is not available in the share host.")
            raise exception.InvalidHost(reason=msg)

        if pool_name in self.pool_dict.keys():
            return self.pool_dict[pool_name]
        else:
            msg = _('Pool [%(pool_name)s] not set in conf.') % {
                'pool_name': pool_name}
            LOG.error(msg)
            raise exception.InfortrendNASException(err=msg)

    def create_share(self, share, share_server=None):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        folder_name = self._extract_lv_name(pool_data)
        share_proto = share['share_proto'].lower()
        share_name = share['id'].replace('-', '')
        share_path = pool_data['path'] + share_name

        command_line = ['folder', 'options', pool_data['id'],
                        folder_name, '-c', share_name]
        self._execute(command_line)

        self._set_share_size(
            pool_data['id'], pool_name, share_name, share['size'])
        self._ensure_protocol_on(share_path, share_proto, share_name)

        LOG.info('Create Share [%(share)s] completed.', {
            'share': share['id']})

        return self._export_location(
            share_name, share_proto, pool_data['path'])

    def _export_location(self, share_name, share_proto, pool_path=None):
        location = []
        location_data = {
            'pool_path': pool_path,
            'share_name': share_name,
        }
        self._check_channels_status()
        for ch in sorted(self.channel_dict.keys()):
            ip = self.channel_dict[ch]
            if share_proto == 'nfs':
                location.append(
                    ip + ':%(pool_path)s%(share_name)s' % location_data)
            elif share_proto == 'cifs':
                location.append(
                    '\\\\' + ip + '\\%(share_name)s' % location_data)
            else:
                msg = _('Unsupported protocol: [%s].') % share_proto
                raise exception.InvalidInput(msg)

        return location

    def _set_share_size(self, pool_id, pool_name, share_name, share_size):
        pool_data = self._get_share_pool_data(pool_name)
        folder_name = self._extract_lv_name(pool_data)
        command_line = ['fquota', 'create', pool_id, folder_name,
                        share_name, str(share_size) + 'G', '-t', 'folder']
        self._execute(command_line)

        LOG.debug('Set Share [%(share_name)s] '
                  'Size [%(share_size)s G] completed.', {
                      'share_name': share_name,
                      'share_size': share_size})
        return

    def _get_share_size(self, pool_id, pool_name, share_name):
        share_size = None
        command_line = ['fquota', 'status', pool_id,
                        share_name, '-t', 'folder']
        rc, quota_status = self._execute(command_line)

        for share_quota in quota_status:
            if share_quota['name'] == share_name:
                share_size = round(_bi_to_gi(float(share_quota['quota'])), 2)
                break

        return share_size

    def delete_share(self, share, share_server=None):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        folder_name = self._extract_lv_name(pool_data)
        share_name = share['id'].replace('-', '')

        if self._check_share_exist(pool_name, share_name):
            command_line = ['folder', 'options', pool_data['id'],
                            folder_name, '-d', share_name]
            self._execute(command_line)
        else:
            LOG.warning('Share [%(share_name)s] is already deleted.', {
                'share_name': share_name})

        LOG.info('Delete Share [%(share)s] completed.', {
            'share': share['id']})

    def _check_share_exist(self, pool_name, share_name):
        path = self.pool_dict[pool_name]['path']
        command_line = ['pagelist', 'folder', path]
        rc, subfolders = self._execute(command_line)
        return any(subfolder['name'] == share_name for subfolder in subfolders)

    def update_access(self, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        self._evict_unauthorized_clients(share, access_rules, share_server)
        access_dict = {}
        for access in access_rules:
            try:
                self._allow_access(share, access, share_server)
            except (exception.InfortrendNASException) as e:
                msg = _('Failed to allow access to client %(access)s, '
                        'reason %(e)s.') % {
                            'access': access['access_to'], 'e': e}
                LOG.error(msg)
                access_dict[access['id']] = 'error'

        return access_dict

    def _evict_unauthorized_clients(self, share, access_rules,
                                    share_server=None):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        share_proto = share['share_proto'].lower()
        share_name = share['id'].replace('-', '')
        share_path = pool_data['path'] + share_name

        access_list = []
        for access in access_rules:
            access_list.append(access['access_to'])

        if share_proto == 'nfs':
            host_ip_list = []
            command_line = ['share', 'status', '-f', share_path]
            rc, nfs_status = self._execute(command_line)
            host_list = nfs_status[0]['nfs_detail']['hostList']
            for host in host_list:
                if host['host'] != '*':
                    host_ip_list.append(host['host'])
            for ip in host_ip_list:
                if ip not in access_list:
                    command_line = ['share', 'options', share_path,
                                    'nfs', '-c', ip]
                    try:
                        self._execute(command_line)
                    except exception.InfortrendNASException:
                        msg = _("Failed to remove share access rule %s") % (ip)
                        LOG.exception(msg)
                        pass

        elif share_proto == 'cifs':
            host_user_list = []
            command_line = ['acl', 'get', share_path]
            rc, cifs_status = self._execute(command_line)
            for cifs_rule in cifs_status:
                if cifs_rule['name']:
                    host_user_list.append(cifs_rule['name'])
            for user in host_user_list:
                if user not in access_list:
                    command_line = ['acl', 'delete', share_path, '-u', user]
                    try:
                        self._execute(command_line)
                    except exception.InfortrendNASException:
                        msg = _("Failed to remove share access rule %s") % (
                            user)
                        LOG.exception(msg)
                        pass

    def _allow_access(self, share, access, share_server=None):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        share_name = share['id'].replace('-', '')
        share_path = pool_data['path'] + share_name
        share_proto = share['share_proto'].lower()
        access_type = access['access_type']
        access_level = access['access_level'] or constants.ACCESS_LEVEL_RW
        access_to = access['access_to']
        ACCESS_LEVEL_MAP = {access_level: access_level}
        msg = self._check_access_legal(share_proto, access_type)
        if msg:
            raise exception.InvalidShareAccess(reason=msg)

        if share_proto == 'nfs':
            command_line = ['share', 'options', share_path, 'nfs',
                            '-h', access_to, '-p', access_level]
            self._execute(command_line)

        elif share_proto == 'cifs':
            if not self._check_user_exist(access_to):
                msg = _('Please create user [%(user)s] in advance.') % {
                    'user': access_to}
                LOG.error(msg)
                raise exception.InfortrendNASException(err=msg)

            if access_level == constants.ACCESS_LEVEL_RW:
                cifs_access = 'f'
            elif access_level == constants.ACCESS_LEVEL_RO:
                cifs_access = 'r'
            try:
                access_level = ACCESS_LEVEL_MAP[access_level]
            except KeyError:
                msg = _('Unsupported access_level: [%s].') % access_level
                raise exception.InvalidInput(msg)

            command_line = ['acl', 'set', share_path,
                            '-u', access_to, '-a', cifs_access]
            self._execute(command_line)

        LOG.info('Share [%(share)s] access to [%(access_to)s] '
                 'level [%(level)s] protocol [%(share_proto)s] completed.', {
                     'share': share['id'],
                     'access_to': access_to,
                     'level': access_level,
                     'share_proto': share_proto})

    def _ensure_protocol_on(self, share_path, share_proto, cifs_name):
        if not self._check_proto_enabled(share_path, share_proto):
            command_line = ['share', share_path, share_proto, 'on']
            if share_proto == 'cifs':
                command_line.extend(['-n', cifs_name])
            self._execute(command_line)

    def _check_proto_enabled(self, share_path, share_proto):
        command_line = ['share', 'status', '-f', share_path]
        rc, share_status = self._execute(command_line)
        if share_status:
            check_enabled = share_status[0][share_proto]
            if check_enabled:
                return True
        return False

    def _check_user_exist(self, user_name):
        command_line = ['useradmin', 'user', 'list']
        rc, user_list = self._execute(command_line)
        for user in user_list:
            if user['Name'] == user_name:
                return True
        return False

    def _check_access_legal(self, share_proto, access_type):
        msg = None
        if share_proto == 'cifs' and access_type != 'user':
            msg = _('Infortrend CIFS share only supports USER access type.')
        elif share_proto == 'nfs' and access_type != 'ip':
            msg = _('Infortrend NFS share only supports IP access type.')
        elif share_proto not in ('nfs', 'cifs'):
            msg = _('Unsupported share protocol [%s].') % share_proto
        return msg

    def get_pool(self, share):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if not pool_name:
            share_name = share['id'].replace('-', '')
            for pool in self.pool_dict.keys():
                if self._check_share_exist(pool, share_name):
                    pool_name = pool
                    break
        return pool_name

    def ensure_share(self, share, share_server=None):
        share_proto = share['share_proto'].lower()
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        share_name = share['id'].replace('-', '')
        return self._export_location(
            share_name, share_proto, pool_data['path'])

    def extend_share(self, share, new_size, share_server=None):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        share_name = share['id'].replace('-', '')
        self._set_share_size(pool_data['id'], pool_name, share_name, new_size)

        LOG.info('Successfully Extend Share [%(share)s] '
                 'to size [%(new_size)s G].', {
                     'share': share['id'],
                     'new_size': new_size})

    def shrink_share(self, share, new_size, share_server=None):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        share_name = share['id'].replace('-', '')
        folder_name = self._extract_lv_name(pool_data)

        command_line = ['fquota', 'status', pool_data['id'],
                        folder_name, '-t', 'folder']
        rc, quota_status = self._execute(command_line)

        for share_quota in quota_status:
            if share_quota['name'] == share_name:
                used_space = round(_bi_to_gi(float(share_quota['used'])), 2)

        if new_size < used_space:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

        self._set_share_size(pool_data['id'], pool_name, share_name, new_size)

        LOG.info('Successfully Shrink Share [%(share)s] '
                 'to size [%(new_size)s G].', {
                     'share': share['id'],
                     'new_size': new_size})

    def manage_existing(self, share, driver_options):
        share_proto = share['share_proto'].lower()
        pool_name = share_utils.extract_host(share['host'], level='pool')
        pool_data = self._get_share_pool_data(pool_name)
        volume_name = self._extract_lv_name(pool_data)
        input_location = share['export_locations'][0]['path']
        share_name = share['id'].replace('-', '')

        ch_ip, folder_name = self._parse_location(input_location, share_proto)

        if not self._check_channel_ip(ch_ip):
            msg = _('Export location ip: [%(ch_ip)s] '
                    'is incorrect, please use data port ip.') % {
                        'ch_ip': ch_ip}
            LOG.error(msg)
            raise exception.InfortrendNASException(err=msg)

        if not self._check_share_exist(pool_name, folder_name):
            msg = _('Can not find folder [%(folder_name)s] '
                    'in pool [%(pool_name)s].') % {
                        'folder_name': folder_name,
                        'pool_name': pool_name}
            LOG.error(msg)
            raise exception.InfortrendNASException(err=msg)

        share_path = pool_data['path'] + folder_name
        self._ensure_protocol_on(share_path, share_proto, share_name)
        share_size = self._get_share_size(
            pool_data['id'], pool_name, folder_name)

        if not share_size:
            msg = _('Folder [%(folder_name)s] has no size limitation, '
                    'please set it first for Openstack management.') % {
                        'folder_name': folder_name}
            LOG.error(msg)
            raise exception.InfortrendNASException(err=msg)

        # rename folder name
        command_line = ['folder', 'options', pool_data['id'], volume_name,
                        '-k', folder_name, share_name]
        self._execute(command_line)

        location = self._export_location(
            share_name, share_proto, pool_data['path'])

        LOG.info('Successfully Manage Infortrend Share [%(folder_name)s], '
                 'Size: [%(size)s G], Protocol: [%(share_proto)s], '
                 'new name: [%(share_name)s].', {
                     'folder_name': folder_name,
                     'size': share_size,
                     'share_proto': share_proto,
                     'share_name': share_name})

        return {'size': share_size, 'export_locations': location}

    def _parse_location(self, input_location, share_proto):
        ip = None
        folder_name = None
        pattern_ip = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        if share_proto == 'nfs':
            pattern_folder = r'[^\/]+$'
            ip = "".join(re.findall(pattern_ip, input_location))
            folder_name = "".join(re.findall(pattern_folder, input_location))

        elif share_proto == 'cifs':
            pattern_folder = r'[^\\]+$'
            ip = "".join(re.findall(pattern_ip, input_location))
            folder_name = "".join(re.findall(pattern_folder, input_location))

        if not (ip and folder_name):
            msg = _('Export location error, please check '
                    'ip: [%(ip)s], folder_name: [%(folder_name)s].') % {
                        'ip': ip,
                        'folder_name': folder_name}
            LOG.error(msg)
            raise exception.InfortrendNASException(err=msg)

        return ip, folder_name

    def _check_channel_ip(self, channel_ip):
        return any(ip == channel_ip for ip in self.channel_dict.values())

    def unmanage(self, share):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        share_name = share['id'].replace('-', '')

        if not self._check_share_exist(pool_name, share_name):
            LOG.warning('Share [%(share_name)s] does not exist.', {
                'share_name': share_name})
            return

        LOG.info('Successfully Unmanaged Share [%(share)s].', {
            'share': share['id']})
