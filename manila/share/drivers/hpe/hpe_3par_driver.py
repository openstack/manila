# Copyright 2015 Hewlett Packard Enterprise Development LP
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

"""HPE 3PAR Driver for OpenStack Manila."""

import datetime
import hashlib
import inspect
import logging
import os
import re

from oslo_config import cfg
from oslo_log import log
import six

from manila.common import config
from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.share import driver
from manila.share.drivers.hpe import hpe_3par_mediator
from manila.share import share_types
from manila import utils

HPE3PAR_OPTS = [
    cfg.StrOpt('hpe3par_api_url',
               default='',
               help="3PAR WSAPI Server Url like "
                    "https://<3par ip>:8080/api/v1",
               deprecated_name='hp3par_api_url'),
    cfg.StrOpt('hpe3par_username',
               default='',
               help="3PAR username with the 'edit' role",
               deprecated_name='hp3par_username'),
    cfg.StrOpt('hpe3par_password',
               default='',
               help="3PAR password for the user specified in hpe3par_username",
               secret=True,
               deprecated_name='hp3par_password'),
    cfg.StrOpt('hpe3par_san_ip',
               default='',
               help="IP address of SAN controller",
               deprecated_name='hp3par_san_ip'),
    cfg.StrOpt('hpe3par_san_login',
               default='',
               help="Username for SAN controller",
               deprecated_name='hp3par_san_login'),
    cfg.StrOpt('hpe3par_san_password',
               default='',
               help="Password for SAN controller",
               secret=True,
               deprecated_name='hp3par_san_password'),
    cfg.PortOpt('hpe3par_san_ssh_port',
                default=22,
                help='SSH port to use with SAN',
                deprecated_name='hp3par_san_ssh_port'),
    cfg.StrOpt('hpe3par_fpg',
               default="OpenStack",
               help="The File Provisioning Group (FPG) to use",
               deprecated_name='hp3par_fpg'),
    cfg.StrOpt('hpe3par_share_ip_address',
               default='',
               help="The IP address for shares not using a share server",
               deprecated_name='hp3par_share_ip_address'),
    cfg.BoolOpt('hpe3par_fstore_per_share',
                default=False,
                help="Use one filestore per share",
                deprecated_name='hp3par_fstore_per_share'),
    cfg.BoolOpt('hpe3par_require_cifs_ip',
                default=False,
                help="Require IP access rules for CIFS (in addition to user)"),
    cfg.BoolOpt('hpe3par_debug',
                default=False,
                help="Enable HTTP debugging to 3PAR",
                deprecated_name='hp3par_debug'),
    cfg.StrOpt('hpe3par_cifs_admin_access_username',
               default='',
               help="File system admin user name for CIFS.",
               deprecated_name='hp3par_cifs_admin_access_username'),
    cfg.StrOpt('hpe3par_cifs_admin_access_password',
               default='',
               help="File system admin password for CIFS.",
               secret=True,
               deprecated_name='hp3par_cifs_admin_access_password'),
    cfg.StrOpt('hpe3par_cifs_admin_access_domain',
               default='LOCAL_CLUSTER',
               help="File system domain for the CIFS admin user.",
               deprecated_name='hp3par_cifs_admin_access_domain'),
    cfg.StrOpt('hpe3par_share_mount_path',
               default='/mnt/',
               help="The path where shares will be mounted when deleting "
                    "nested file trees.",
               deprecated_name='hpe3par_share_mount_path'),
]

CONF = cfg.CONF
CONF.register_opts(HPE3PAR_OPTS)

LOG = log.getLogger(__name__)


class HPE3ParShareDriver(driver.ShareDriver):
    """HPE 3PAR driver for Manila.

    Supports NFS and CIFS protocols on arrays with File Persona.

    Version history:
        1.0.0 - Begin Liberty development (post-Kilo)
        1.0.1 - Report thin/dedup/hp_flash_cache capabilities
        1.0.2 - Add share server/share network support
        2.0.0 - Rebranded HP to HPE
        2.0.1 - Add access_level (e.g. read-only support)
        2.0.2 - Add extend/shrink
        2.0.3 - Remove file tree on delete when using nested shares #1538800

    """

    VERSION = "2.0.3"

    def __init__(self, *args, **kwargs):
        super(HPE3ParShareDriver, self).__init__((True, False),
                                                 *args,
                                                 **kwargs)

        self.configuration = kwargs.get('configuration', None)
        self.configuration.append_config_values(HPE3PAR_OPTS)
        self.configuration.append_config_values(driver.ssh_opts)
        self.configuration.append_config_values(config.global_opts)
        self.fpg = None
        self.vfs = None
        self.share_ip_address = None
        self._hpe3par = None  # mediator between driver and client

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""

        LOG.info(_LI("Starting share driver %(driver_name)s (%(version)s)"),
                 {'driver_name': self.__class__.__name__,
                  'version': self.VERSION})

        if not self.driver_handles_share_servers:
            self.share_ip_address = self.configuration.hpe3par_share_ip_address
            if not self.share_ip_address:
                raise exception.HPE3ParInvalid(
                    _("Unsupported configuration. "
                      "hpe3par_share_ip_address must be set when "
                      "driver_handles_share_servers is False."))

        mediator = hpe_3par_mediator.HPE3ParMediator(
            hpe3par_username=self.configuration.hpe3par_username,
            hpe3par_password=self.configuration.hpe3par_password,
            hpe3par_api_url=self.configuration.hpe3par_api_url,
            hpe3par_debug=self.configuration.hpe3par_debug,
            hpe3par_san_ip=self.configuration.hpe3par_san_ip,
            hpe3par_san_login=self.configuration.hpe3par_san_login,
            hpe3par_san_password=self.configuration.hpe3par_san_password,
            hpe3par_san_ssh_port=self.configuration.hpe3par_san_ssh_port,
            hpe3par_fstore_per_share=(self.configuration
                                      .hpe3par_fstore_per_share),
            hpe3par_require_cifs_ip=self.configuration.hpe3par_require_cifs_ip,
            hpe3par_share_ip_address=(
                self.configuration.hpe3par_share_ip_address),
            hpe3par_cifs_admin_access_username=(
                self.configuration.hpe3par_cifs_admin_access_username),
            hpe3par_cifs_admin_access_password=(
                self.configuration.hpe3par_cifs_admin_access_password),
            hpe3par_cifs_admin_access_domain=(
                self.configuration.hpe3par_cifs_admin_access_domain),
            hpe3par_share_mount_path=(
                self.configuration.hpe3par_share_mount_path),
            my_ip=self.configuration.my_ip,
            ssh_conn_timeout=self.configuration.ssh_conn_timeout,
        )

        mediator.do_setup()

        # FPG must be configured and must exist.
        self.fpg = self.configuration.safe_get('hpe3par_fpg')
        # Validate the FPG and discover the VFS
        # This also validates the client, connection, firmware, WSAPI, FPG...
        self.vfs = mediator.get_vfs_name(self.fpg)

        # Don't set _hpe3par until it is ready. Otherwise _update_stats fails.
        self._hpe3par = mediator

    def check_for_setup_error(self):

        try:
            # Log the source SHA for support.  Only do this with DEBUG.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug('HPE3ParShareDriver SHA1: %s',
                          self.sha1_hash(HPE3ParShareDriver))
                LOG.debug('HPE3ParMediator SHA1: %s',
                          self.sha1_hash(hpe_3par_mediator.HPE3ParMediator))
        except Exception as e:
            # Don't let any exceptions during the SHA1 logging interfere
            # with startup.  This is just debug info to identify the source
            # code.  If it doesn't work, just log a debug message.
            LOG.debug('Source code SHA1 not logged due to: %s',
                      six.text_type(e))

    @staticmethod
    def sha1_hash(clazz):
        """Get the SHA1 hash for the source of a class."""
        source_file = inspect.getsourcefile(clazz)
        file_size = os.path.getsize(source_file)

        sha1 = hashlib.sha1()
        sha1.update(("blob %u\0" % file_size).encode('utf-8'))

        with open(source_file, 'rb') as f:
            sha1.update(f.read())

        return sha1.hexdigest()

    def get_network_allocations_number(self):
        return 1

    @staticmethod
    def _validate_network_type(network_type):
        if network_type not in ('flat', 'vlan', None):
            reason = _('Invalid network type. %s is not supported by the '
                       '3PAR driver.')
            raise exception.NetworkBadConfigurationException(
                reason=reason % network_type)

    def _setup_server(self, network_info, metadata=None):
        LOG.debug("begin _setup_server with %s", network_info)

        self._validate_network_type(network_info['network_type'])

        ip = network_info['network_allocations'][0]['ip_address']
        subnet = utils.cidr_to_netmask(network_info['cidr'])
        vlantag = network_info['segmentation_id']

        self._hpe3par.create_fsip(ip, subnet, vlantag, self.fpg, self.vfs)

        return {
            'share_server_name': network_info['server_id'],
            'share_server_id': network_info['server_id'],
            'ip': ip,
            'subnet': subnet,
            'vlantag': vlantag if vlantag else 0,
            'fpg': self.fpg,
            'vfs': self.vfs,
        }

    def _teardown_server(self, server_details, security_services=None):
        LOG.debug("begin _teardown_server with %s", server_details)

        self._hpe3par.remove_fsip(server_details.get('ip'),
                                  server_details.get('fpg'),
                                  server_details.get('vfs'))

    def _get_share_ip(self, share_server):
        return share_server['backend_details'].get('ip') if share_server else (
            self.share_ip_address)

    @staticmethod
    def _build_export_location(protocol, ip, path):

        if not ip:
            message = _('Failed to build export location due to missing IP.')
            raise exception.InvalidInput(message)

        if not path:
            message = _('Failed to build export location due to missing path.')
            raise exception.InvalidInput(message)

        if protocol == 'NFS':
            location = ':'.join((ip, path))
        elif protocol == 'CIFS':
            location = '\\\\%s\%s' % (ip, path)
        else:
            message = _('Invalid protocol. Expected NFS or CIFS. '
                        'Got %s.') % protocol
            raise exception.InvalidInput(message)

        return location

    @staticmethod
    def build_share_comment(share):
        """Create an informational only comment to help admins and testers."""

        info = {
            'name': share['display_name'],
            'host': share['host'],
            'now': datetime.datetime.now().strftime('%H%M%S'),
        }

        acceptable = re.compile('[^a-zA-Z0-9_=:@# \-]+', re.UNICODE)
        comment = ("OpenStack Manila - host=%(host)s  orig_name=%(name)s "
                   "created=%(now)s" % info)

        return acceptable.sub('_', comment)[:254]  # clean and truncate

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""

        ip = self._get_share_ip(share_server)

        protocol = share['share_proto']
        extra_specs = share_types.get_extra_specs_from_share(share)

        path = self._hpe3par.create_share(
            share['project_id'],
            share['id'],
            protocol,
            extra_specs,
            self.fpg, self.vfs,
            size=share['size'],
            comment=self.build_share_comment(share)
        )

        return self._build_export_location(protocol, ip, path)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""

        ip = self._get_share_ip(share_server)

        protocol = share['share_proto']
        extra_specs = share_types.get_extra_specs_from_share(share)

        path = self._hpe3par.create_share_from_snapshot(
            share['id'],
            protocol,
            extra_specs,
            share['project_id'],
            snapshot['share_id'],
            snapshot['id'],
            self.fpg,
            self.vfs,
            comment=self.build_share_comment(share)
        )

        return self._build_export_location(protocol, ip, path)

    def delete_share(self, context, share, share_server=None):
        """Deletes share and its fstore."""

        self._hpe3par.delete_share(share['project_id'],
                                   share['id'],
                                   share['share_proto'],
                                   self.fpg,
                                   self.vfs)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""

        self._hpe3par.create_snapshot(snapshot['share']['project_id'],
                                      snapshot['share']['id'],
                                      snapshot['share']['share_proto'],
                                      snapshot['id'],
                                      self.fpg,
                                      self.vfs)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""

        self._hpe3par.delete_snapshot(snapshot['share']['project_id'],
                                      snapshot['share']['id'],
                                      snapshot['share']['share_proto'],
                                      snapshot['id'],
                                      self.fpg,
                                      self.vfs)

    def ensure_share(self, context, share, share_server=None):
        pass

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""

        extra_specs = None
        if 'NFS' == share['share_proto']:  # Avoiding DB call otherwise
            extra_specs = share_types.get_extra_specs_from_share(share)

        self._hpe3par.allow_access(share['project_id'],
                                   share['id'],
                                   share['share_proto'],
                                   extra_specs,
                                   access['access_type'],
                                   access['access_to'],
                                   access['access_level'],
                                   self.fpg,
                                   self.vfs)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self._hpe3par.deny_access(share['project_id'],
                                  share['id'],
                                  share['share_proto'],
                                  access['access_type'],
                                  access['access_to'],
                                  access['access_level'],
                                  self.fpg,
                                  self.vfs)

    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""
        self._hpe3par.resize_share(share['project_id'],
                                   share['id'],
                                   share['share_proto'],
                                   new_size,
                                   share['size'],
                                   self.fpg,
                                   self.vfs)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        self._hpe3par.resize_share(share['project_id'],
                                   share['id'],
                                   share['share_proto'],
                                   new_size,
                                   share['size'],
                                   self.fpg,
                                   self.vfs)

    def _update_share_stats(self):
        """Retrieve stats info from share group."""

        backend_name = self.configuration.safe_get(
            'share_backend_name') or "HPE_3PAR"

        max_over_subscription_ratio = self.configuration.safe_get(
            'max_over_subscription_ratio')

        reserved_share_percentage = self.configuration.safe_get(
            'reserved_share_percentage')
        if reserved_share_percentage is None:
            reserved_share_percentage = 0

        stats = {
            'share_backend_name': backend_name,
            'driver_handles_share_servers': self.driver_handles_share_servers,
            'vendor_name': 'HPE',
            'driver_version': self.VERSION,
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0,
            'free_capacity_gb': 0,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': reserved_share_percentage,
            'max_over_subscription_ratio': max_over_subscription_ratio,
            'qos': False,
            'thin_provisioning': True,  # 3PAR default is thin
        }

        if not self._hpe3par:
            LOG.info(
                _LI("Skipping capacity and capabilities update. Setup has not "
                    "completed."))
        else:
            fpg_status = self._hpe3par.get_fpg_status(self.fpg)
            LOG.debug("FPG status = %s.", fpg_status)
            stats.update(fpg_status)

        super(HPE3ParShareDriver, self)._update_share_stats(stats)
