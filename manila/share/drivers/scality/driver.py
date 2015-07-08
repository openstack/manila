# Copyright (c) 2015 Scality
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

import oslo_log.log

from oslo_concurrency import processutils
from oslo_config import cfg

from manila import utils, exception
from manila.i18n import _
from manila.share import driver

log = oslo_log.log.getLogger(__name__)

share_opts = [
    cfg.StrOpt('export_ip', help='IP reachable from the tenant networks on '
              'which the shares are exposed'),
    cfg.StrOpt('export_management_host',
               help='IP/hostname of the machine exporting ring volumes'),
    cfg.IntOpt('export_management_port',
               default=22,
               help='Port that sshd is listening on for management tasks'),
    cfg.StrOpt('management_user',
               help='User for management tasks'),
    cfg.StrOpt('ssh_key_path',
               help='Path to the SSH key of the management user'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)


class ScalityShareDriver(driver.ShareDriver):
    """Scality Ring driver for Manila.

    Supports NFS through the sfused NFS connector.
    """
    # Cli exit codes
    EXPORT_NOT_FOUND = 10

    ACCESS_EXISTS = 11

    ACCESS_NOT_FOUND = 12

    # Driver version
    VERSION = '1.0'

    NFS_PROTOCOL = 'NFS'

    def __init__(self, *args, **kwargs):
        super(ScalityShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(share_opts)
        self._config_check()

        self.export_ip = self.configuration.export_ip
        self.ssh_pool = utils.SSHPool(
            ip=self.configuration.export_management_host,
            port=self.configuration.export_management_port,
            conn_timeout=None,
            login=self.configuration.management_user,
            privatekey=self.configuration.ssh_key_path,
        )

    def _config_check(self):
        """Validate configuration settings."""
        log.debug('Validating configuration')
        required = ('export_management_host', 'management_user', 'export_ip')
        for config_item in required:
            if getattr(self.configuration, config_item) is None:
                msg = _("'%s' must be configured" % config_item)
                raise exception.ManilaException(msg)

    def _management_call(self, command):
        """Send a command over ssh to the ring management host.

        :param command: command to execute
        :param command: string
        :returns: tuple of (stdout, stderr) with command output
        """
        cmd = 'sudo scality-manila-utils %s' % command
        return processutils.ssh_execute(self.ssh_pool.get(), cmd)

    def _location_from_id(self, share_id):
        """Format an export location from a share_id.

        :param share_id: share id to format
        :type share_id: string
        :returns: string
        """
        return "%s:/%s" % (self.export_ip, share_id)

    def check_for_setup_error(self):
        """Check that the management host is up and ready."""
        log.debug('Checking management server prerequisites')
        self._management_call('check')

    def create_share(self, context, share, share_server=None):
        if share['share_proto'] != self.NFS_PROTOCOL:
            msg = _("Protocol '%s' is not supported" % share['share_proto'])
            raise exception.InvalidInput(msg)

        command = 'create %s' % share['id']
        self._management_call(command)

        return self._location_from_id(share['id'])

    def ensure_share(self, context, share, share_server=None):
        # Export locations are derived from the `export_ip` configuration
        # parameter, and may thus change between service restarts. It is
        # therefor always returned here if the share exists.
        try:
            self._management_call('get %s' % share['id'])

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%s' (%s) not found" % (share['name'], share['id']))
                raise exception.InvalidShare(reason=msg)

            else:
                raise

        return self._location_from_id(share['id'])

    def allow_access(self, context, share, access, share_server=None):
        self._enforce_ip_acl(access)

        command = 'grant %s %s %s' % (share['id'], access['access_to'],
                                      access['access_level'])
        try:
            self._management_call(command)

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.ACCESS_EXISTS:
                raise exception.ShareAccessExists(
                    access_type=access['access_type'],
                    access=access['access_to']
                )

            elif e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%s' (%s) not found" % (share['name'], share['id']))
                raise exception.InvalidShare(reason=msg)

            else:
                raise

    def deny_access(self, context, share, access, share_server=None):
        self._enforce_ip_acl(access)

        command = 'revoke %s %s' % (share['id'], access['access_to'])
        try:
            self._management_call(command)

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.ACCESS_NOT_FOUND:
                msg = _("%s does not exist" % access['access_to'])
                raise exception.InvalidShareAccess(reason=msg)

            elif e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%s' (%s) not found" % (share['name'], share['id']))
                raise exception.InvalidShare(reason=msg)

            else:
                raise

    def _update_share_stats(self):
        backend_name = self.configuration.safe_get(
            'share_backend_name') or 'Scality Ring Driver'

        stats = {
            'share_backend_name': backend_name,
            'vendor_name': 'Scality',
            'storage_protocol': self.NFS_PROTOCOL,
            'driver_version': self.VERSION,
        }

        super(ScalityShareDriver, self)._update_share_stats(stats)

    def _enforce_ip_acl(self, access):
        """Check that the access is IP based."""
        if access['access_type'] != 'ip':
            raise exception.ManilaException('Only IP restrictions supported')
