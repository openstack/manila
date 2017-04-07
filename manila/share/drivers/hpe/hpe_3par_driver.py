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
import os
import re

from oslo_config import cfg
from oslo_config import types
from oslo_log import log
import six

from manila.common import config
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.hpe import hpe_3par_mediator
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)


class FPG(types.String, types.IPAddress):
    """FPG type.

    Used to represent multiple pools per backend values.
    Converts configuration value to an FPGs value.
    FPGs value format::

        FPG name, IP address 1, IP address 2, ..., IP address 4

    where FPG name is a string value,
    IP address is of type types.IPAddress

    Optionally doing range checking.
    If value is whitespace or empty string will raise error

    :param min_ip: Optional check that number of min IP address of VFS.
    :param max_ip: Optional check that number of max IP address of VFS.
    :param type_name: Type name to be used in the sample config file.

    """

    MAX_SUPPORTED_IP_PER_VFS = 4

    def __init__(self, min_ip=0, max_ip=MAX_SUPPORTED_IP_PER_VFS,
                 type_name='FPG'):
        types.String.__init__(self, type_name=type_name)
        types.IPAddress.__init__(self, type_name=type_name)

        if max_ip < min_ip:
            msg = _("Pool's max acceptable IP cannot be less than min.")
            raise exception.HPE3ParInvalid(err=msg)

        if min_ip < 0:
            msg = _("Pools must be configured with zero or more IPs.")
            raise exception.HPE3ParInvalid(err=msg)

        if max_ip > FPG.MAX_SUPPORTED_IP_PER_VFS:
            msg = (_("Pool's max acceptable IP cannot be greater than "
                     "supported value=%s.") % FPG.MAX_SUPPORTED_IP_PER_VFS)
            raise exception.HPE3ParInvalid(err=msg)

        self.min_ip = min_ip
        self.max_ip = max_ip

    def __call__(self, value):
        if value is None or value.strip(' ') is '':
            message = _("Invalid configuration. hpe3par_fpg must be set.")
            LOG.error(message)
            raise exception.HPE3ParInvalid(err=message)

        ips = []
        values = value.split(",")
        # Extract pool name
        pool_name = values.pop(0).strip()

        # values will now be ['ip1', ...]
        if len(values) < self.min_ip:
            msg = (_("Require at least %s IPs configured per "
                     "pool") % self.min_ip)
            raise exception.HPE3ParInvalid(err=msg)
        if len(values) > self.max_ip:
            msg = (_("Cannot configure IPs more than max supported "
                     "%s IPs per pool") % self.max_ip)
            raise exception.HPE3ParInvalid(err=msg)

        for ip_addr in values:
            ip_addr = types.String.__call__(self, ip_addr.strip())
            try:
                ips.append(types.IPAddress.__call__(self, ip_addr))
            except ValueError as verror:
                raise exception.HPE3ParInvalid(err=verror)
        fpg = {pool_name: ips}
        return fpg

    def __repr__(self):
        return 'FPG'

    def _formatter(self, value):
        return six.text_type(value)

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
    cfg.HostAddressOpt('hpe3par_san_ip',
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
    cfg.MultiOpt('hpe3par_fpg',
                 item_type=FPG(min_ip=0, max_ip=FPG.MAX_SUPPORTED_IP_PER_VFS),
                 help="The File Provisioning Group (FPG) to use",
                 deprecated_name='hp3par_fpg'),
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


def to_list(var):
    """Convert var to list type if not"""
    if isinstance(var, six.string_types):
        return [var]
    else:
        return var


class HPE3ParShareDriver(driver.ShareDriver):
    """HPE 3PAR driver for Manila.

    Supports NFS and CIFS protocols on arrays with File Persona.

    Version history::

        1.0.0 - Begin Liberty development (post-Kilo)
        1.0.1 - Report thin/dedup/hp_flash_cache capabilities
        1.0.2 - Add share server/share network support
        2.0.0 - Rebranded HP to HPE
        2.0.1 - Add access_level (e.g. read-only support)
        2.0.2 - Add extend/shrink
        2.0.3 - Remove file tree on delete when using nested shares #1538800
        2.0.4 - Reduce the fsquota by share size
                when a share is deleted #1582931
        2.0.5 - Add update_access support
        2.0.6 - Multi pool support per backend
        2.0.7 - Fix get_vfs() to correctly validate conf IP addresses at
                boot up #1621016
        2.0.8 - Replace ConsistencyGroup with ShareGroup

    """

    VERSION = "2.0.8"

    def __init__(self, *args, **kwargs):
        super(HPE3ParShareDriver, self).__init__((True, False),
                                                 *args,
                                                 **kwargs)

        self.configuration = kwargs.get('configuration', None)
        self.configuration.append_config_values(HPE3PAR_OPTS)
        self.configuration.append_config_values(driver.ssh_opts)
        self.configuration.append_config_values(config.global_opts)
        self.fpgs = {}
        self._hpe3par = None  # mediator between driver and client

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""

        LOG.info("Starting share driver %(driver_name)s (%(version)s)",
                 {'driver_name': self.__class__.__name__,
                  'version': self.VERSION})

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

        def _validate_pool_ips(addresses, conf_pool_ips):
            # Pool configured IP addresses should be subset of IP addresses
            # retured from vfs
            if not set(conf_pool_ips) <= set(addresses):
                msg = _("Incorrect configuration. "
                        "Configuration pool IP address did not match with "
                        "IP addresses at 3par array")
                raise exception.HPE3ParInvalid(err=msg)

        def _construct_fpg():
            # FPG must be configured and must exist.
            # self.configuration.safe_get('hpe3par_fpg') will have value in
            # following format:
            # [ {'pool_name':['ip_addr', 'ip_addr', ...]}, ... ]
            for fpg in self.configuration.safe_get('hpe3par_fpg'):
                pool_name = list(fpg)[0]
                conf_pool_ips = fpg[pool_name]

                # Validate the FPG and discover the VFS
                # This also validates the client, connection, firmware, WSAPI,
                # FPG...
                vfs_info = mediator.get_vfs(pool_name)
                if self.driver_handles_share_servers:
                    # Use discovered IP(s) from array
                    self.fpgs[pool_name] = {
                        vfs_info['vfsname']: vfs_info['vfsip']['address']}
                elif conf_pool_ips == []:
                    # not DHSS and IPs not configured in manila.conf.
                    if not vfs_info['vfsip']['address']:
                        msg = _("Unsupported configuration. "
                                "hpe3par_fpg must have IP address "
                                "or be discoverable at 3PAR")
                        LOG.error(msg)
                        raise exception.HPE3ParInvalid(err=msg)
                    else:
                        # Use discovered pool ips
                        self.fpgs[pool_name] = {
                            vfs_info['vfsname']: vfs_info['vfsip']['address']}
                else:
                    # not DHSS and IPs configured in manila.conf
                    _validate_pool_ips(vfs_info['vfsip']['address'],
                                       conf_pool_ips)
                    self.fpgs[pool_name] = {
                        vfs_info['vfsname']: conf_pool_ips}

        _construct_fpg()

        # Don't set _hpe3par until it is ready. Otherwise _update_stats fails.
        self._hpe3par = mediator

    def _get_pool_location_from_share_host(self, share_instance_host):
        # Return pool name, vfs, IPs for a pool from share instance host
        pool_name = share_utils.extract_host(share_instance_host, level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       share_instance_host)
            raise exception.InvalidHost(reason=message)

        if pool_name not in self.fpgs:
            message = (_("Pool location lookup failed. "
                         "Could not find pool %s") %
                       pool_name)
            raise exception.InvalidHost(reason=message)

        vfs = list(self.fpgs[pool_name])[0]
        ips = self.fpgs[pool_name][vfs]

        return (pool_name, vfs, ips)

    def _get_pool_location(self, share, share_server=None):
        # Return pool name, vfs, IPs for a pool from share host field
        # Use share_server if provided, instead of self.fpgs
        if share_server is not None:
            # When DHSS
            ips = share_server['backend_details'].get('ip')
            ips = to_list(ips)
            vfs = share_server['backend_details'].get('vfs')
            pool_name = share_server['backend_details'].get('fpg')
            return (pool_name, vfs, ips)
        else:
            # When DHSS = false
            return self._get_pool_location_from_share_host(share['host'])

    def check_for_setup_error(self):

        try:
            # Log the source SHA for support.  Only do this with DEBUG.
            if LOG.isEnabledFor(log.DEBUG):
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

    def choose_share_server_compatible_with_share(self, context, share_servers,
                                                  share, snapshot=None,
                                                  share_group=None):
        """Method that allows driver to choose share server for provided share.

        If compatible share-server is not found, method should return None.

        :param context: Current context
        :param share_servers: list with share-server models
        :param share:  share model
        :param snapshot: snapshot model
        :param share_group: ShareGroup model with shares
        :returns: share-server or None
        """
        # If creating in a share group, raise exception
        if share_group:
            msg = _("HPE 3PAR driver does not support share group")
            raise exception.InvalidRequest(message=msg)

        pool_name = share_utils.extract_host(share['host'], level='pool')
        for share_server in share_servers:
            if share_server['backend_details'].get('fpg') == pool_name:
                return share_server
        return None

    @staticmethod
    def _validate_network_type(network_type):
        if network_type not in ('flat', 'vlan', None):
            reason = _('Invalid network type. %s is not supported by the '
                       '3PAR driver.')
            raise exception.NetworkBadConfigurationException(
                reason=reason % network_type)

    def _create_share_server(self, network_info, request_host=None):
        """Is called to create/setup share server"""
        # Return pool name, vfs, IPs for a pool
        pool_name, vfs, ips = self._get_pool_location_from_share_host(
            request_host)

        ip = network_info['network_allocations'][0]['ip_address']
        if ip not in ips:
            # Besides DHSS, admin could have setup IP to VFS directly on array
            if len(ips) > (FPG.MAX_SUPPORTED_IP_PER_VFS - 1):
                message = (_("Pool %s has exceeded 3PAR's "
                             "max supported VFS IP address") % pool_name)
                LOG.error(message)
                raise exception.Invalid(message)

            subnet = utils.cidr_to_netmask(network_info['cidr'])
            vlantag = network_info['segmentation_id']

            self._hpe3par.create_fsip(ip, subnet, vlantag, pool_name, vfs)
            # Update in global saved config, self.fpgs[pool_name]
            ips.append(ip)

        return {'share_server_name': network_info['server_id'],
                'share_server_id': network_info['server_id'],
                'ip': ip,
                'subnet': subnet,
                'vlantag': vlantag if vlantag else 0,
                'fpg': pool_name,
                'vfs': vfs}

    def _setup_server(self, network_info, metadata=None):

        LOG.debug("begin _setup_server with %s", network_info)

        self._validate_network_type(network_info['network_type'])
        if metadata is not None and metadata['request_host'] is not None:
            return self._create_share_server(network_info,
                                             metadata['request_host'])

    def _teardown_server(self, server_details, security_services=None):
        LOG.debug("begin _teardown_server with %s", server_details)
        fpg = server_details.get('fpg')
        vfs = server_details.get('vfs')
        ip = server_details.get('ip')
        self._hpe3par.remove_fsip(ip, fpg, vfs)
        if ip in self.fpgs[fpg][vfs]:
            self.fpgs[fpg][vfs].remove(ip)

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

        fpg, vfs, ips = self._get_pool_location(share, share_server)

        protocol = share['share_proto']
        extra_specs = share_types.get_extra_specs_from_share(share)

        path = self._hpe3par.create_share(
            share['project_id'],
            share['id'],
            protocol,
            extra_specs,
            fpg, vfs,
            size=share['size'],
            comment=self.build_share_comment(share)
        )

        return self._hpe3par.build_export_locations(protocol, ips, path)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""

        fpg, vfs, ips = self._get_pool_location(share, share_server)

        protocol = share['share_proto']
        extra_specs = share_types.get_extra_specs_from_share(share)

        path = self._hpe3par.create_share_from_snapshot(
            share['id'],
            protocol,
            extra_specs,
            share['project_id'],
            snapshot['share_id'],
            snapshot['id'],
            fpg,
            vfs,
            ips,
            size=share['size'],
            comment=self.build_share_comment(share)
        )

        return self._hpe3par.build_export_locations(protocol, ips, path)

    def delete_share(self, context, share, share_server=None):
        """Deletes share and its fstore."""

        fpg, vfs, ips = self._get_pool_location(share, share_server)
        self._hpe3par.delete_share(share['project_id'],
                                   share['id'],
                                   share['size'],
                                   share['share_proto'],
                                   fpg,
                                   vfs,
                                   ips[0])

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""

        fpg, vfs, ips = self._get_pool_location(snapshot['share'],
                                                share_server)
        self._hpe3par.create_snapshot(snapshot['share']['project_id'],
                                      snapshot['share']['id'],
                                      snapshot['share']['share_proto'],
                                      snapshot['id'],
                                      fpg,
                                      vfs)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""

        fpg, vfs, ips = self._get_pool_location(snapshot['share'],
                                                share_server)
        self._hpe3par.delete_snapshot(snapshot['share']['project_id'],
                                      snapshot['share']['id'],
                                      snapshot['share']['share_proto'],
                                      snapshot['id'],
                                      fpg,
                                      vfs)

    def ensure_share(self, context, share, share_server=None):
        pass

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access to the share."""
        extra_specs = None
        if 'NFS' == share['share_proto']:  # Avoiding DB call otherwise
            extra_specs = share_types.get_extra_specs_from_share(share)

        fpg, vfs, ips = self._get_pool_location(share, share_server)
        self._hpe3par.update_access(share['project_id'],
                                    share['id'],
                                    share['share_proto'],
                                    extra_specs,
                                    access_rules,
                                    add_rules,
                                    delete_rules,
                                    fpg,
                                    vfs)

    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""

        fpg, vfs, ips = self._get_pool_location(share, share_server)
        self._hpe3par.resize_share(share['project_id'],
                                   share['id'],
                                   share['share_proto'],
                                   new_size,
                                   share['size'],
                                   fpg,
                                   vfs)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""

        fpg, vfs, ips = self._get_pool_location(share, share_server)
        self._hpe3par.resize_share(share['project_id'],
                                   share['id'],
                                   share['share_proto'],
                                   new_size,
                                   share['size'],
                                   fpg,
                                   vfs)

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
                "Skipping capacity and capabilities update. Setup has not "
                "completed.")
        else:
            for fpg in self.fpgs:
                fpg_status = self._hpe3par.get_fpg_status(fpg)
                fpg_status['reserved_percentage'] = reserved_share_percentage
                LOG.debug("FPG status = %s.", fpg_status)
                stats.setdefault('pools', []).append(fpg_status)

        super(HPE3ParShareDriver, self)._update_share_stats(stats)
