# Copyright (c) 2016 Red Hat, Inc.
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


import socket
import sys

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers import ganesha
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila.share import share_types

try:
    import ceph_volume_client
    ceph_module_found = True
except ImportError as e:
    ceph_volume_client = None
    ceph_module_found = False


CEPHX_ACCESS_TYPE = "cephx"

# The default Ceph administrative identity
CEPH_DEFAULT_AUTH_ID = "admin"

DEFAULT_VOLUME_MODE = '755'


LOG = log.getLogger(__name__)

cephfs_opts = [
    cfg.StrOpt('cephfs_conf_path',
               default="",
               help="Fully qualified path to the ceph.conf file."),
    cfg.StrOpt('cephfs_cluster_name',
               help="The name of the cluster in use, if it is not "
                    "the default ('ceph')."
               ),
    cfg.StrOpt('cephfs_auth_id',
               default="manila",
               help="The name of the ceph auth identity to use."
               ),
    cfg.BoolOpt('cephfs_enable_snapshots',
                default=False,
                help="Whether to enable snapshots in this driver."
                ),
    cfg.StrOpt('cephfs_protocol_helper_type',
               default="CEPHFS",
               choices=['CEPHFS', 'NFS'],
               ignore_case=True,
               help="The type of protocol helper to use. Default is "
                    "CEPHFS."
               ),
    cfg.BoolOpt('cephfs_ganesha_server_is_remote',
                default=False,
                help="Whether the NFS-Ganesha server is remote to the driver."
                ),
    cfg.StrOpt('cephfs_ganesha_server_ip',
               help="The IP address of the NFS-Ganesha server."),
    cfg.StrOpt('cephfs_ganesha_server_username',
               default='root',
               help="The username to authenticate as in the remote "
                    "NFS-Ganesha server host."),
    cfg.StrOpt('cephfs_ganesha_path_to_private_key',
               help="The path of the driver host's private SSH key file."),
    cfg.StrOpt('cephfs_ganesha_server_password',
               secret=True,
               help="The password to authenticate as the user in the remote "
                    "Ganesha server host. This is not required if "
                    "'cephfs_ganesha_path_to_private_key' is configured."),
    cfg.StrOpt('cephfs_volume_mode',
               default=DEFAULT_VOLUME_MODE,
               help="The read/write/execute permissions mode for CephFS "
                    "volumes, snapshots, and snapshot groups expressed in "
                    "Octal as with linux 'chmod' or 'umask' commands."),
]


CONF = cfg.CONF
CONF.register_opts(cephfs_opts)


def cephfs_share_path(share):
    """Get VolumePath from Share."""
    return ceph_volume_client.VolumePath(
        share['share_group_id'], share['id'])


class CephFSDriver(driver.ExecuteMixin, driver.GaneshaMixin,
                   driver.ShareDriver,):
    """Driver for the Ceph Filesystem."""

    def __init__(self, *args, **kwargs):
        super(CephFSDriver, self).__init__(False, *args, **kwargs)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'CephFS'

        self._volume_client = None

        self.configuration.append_config_values(cephfs_opts)

        try:
            self._cephfs_volume_mode = int(
                self.configuration.cephfs_volume_mode, 8)
        except ValueError:
            msg = _("Invalid CephFS volume mode %s")
            raise exception.BadConfigurationException(
                msg % self.configuration.cephfs_volume_mode)

    def do_setup(self, context):
        if self.configuration.cephfs_protocol_helper_type.upper() == "CEPHFS":
            protocol_helper_class = getattr(
                sys.modules[__name__], 'NativeProtocolHelper')
        else:
            protocol_helper_class = getattr(
                sys.modules[__name__], 'NFSProtocolHelper')

        self.protocol_helper = protocol_helper_class(
            self._execute,
            self.configuration,
            ceph_vol_client=self.volume_client)

        self.protocol_helper.init_helper()

    def _update_share_stats(self):
        stats = self.volume_client.rados.get_cluster_stats()

        total_capacity_gb = stats['kb'] * units.Mi
        free_capacity_gb = stats['kb_avail'] * units.Mi

        data = {
            'vendor_name': 'Ceph',
            'driver_version': '1.0',
            'share_backend_name': self.backend_name,
            'storage_protocol': self.configuration.safe_get(
                'cephfs_protocol_helper_type'),
            'pools': [
                {
                    'pool_name': 'cephfs',
                    'total_capacity_gb': total_capacity_gb,
                    'free_capacity_gb': free_capacity_gb,
                    'qos': 'False',
                    'reserved_percentage': 0,
                    'dedupe': [False],
                    'compression': [False],
                    'thin_provisioning': [False]
                }
            ],
            'total_capacity_gb': total_capacity_gb,
            'free_capacity_gb': free_capacity_gb,
            'snapshot_support': self.configuration.safe_get(
                'cephfs_enable_snapshots'),
        }
        super(CephFSDriver, self)._update_share_stats(data)

    def _to_bytes(self, gigs):
        """Convert a Manila size into bytes.

        Manila uses gibibytes everywhere.

        :param gigs: integer number of gibibytes.
        :return: integer number of bytes.
        """
        return gigs * units.Gi

    @property
    def volume_client(self):
        if self._volume_client:
            return self._volume_client

        if not ceph_module_found:
            raise exception.ManilaException(
                _("Ceph client libraries not found.")
            )

        conf_path = self.configuration.safe_get('cephfs_conf_path')
        cluster_name = self.configuration.safe_get('cephfs_cluster_name')
        auth_id = self.configuration.safe_get('cephfs_auth_id')
        self._volume_client = ceph_volume_client.CephFSVolumeClient(
            auth_id, conf_path, cluster_name)
        LOG.info("[%(be)s}] Ceph client found, connecting...",
                 {"be": self.backend_name})
        if auth_id != CEPH_DEFAULT_AUTH_ID:
            # Evict any other manila sessions.  Only do this if we're
            # using a client ID that isn't the default admin ID, to avoid
            # rudely disrupting anyone else.
            premount_evict = auth_id
        else:
            premount_evict = None
        try:
            self._volume_client.connect(premount_evict=premount_evict)
        except Exception:
            self._volume_client = None
            raise
        else:
            LOG.info("[%(be)s] Ceph client connection complete.",
                     {"be": self.backend_name})

        return self._volume_client

    def create_share(self, context, share, share_server=None):
        """Create a CephFS volume.

        :param context: A RequestContext.
        :param share: A Share.
        :param share_server: Always None for CephFS native.
        :return: The export locations dictionary.
        """
        requested_proto = share['share_proto'].upper()
        supported_proto = (
            self.configuration.cephfs_protocol_helper_type.upper())
        if (requested_proto != supported_proto):
            msg = _("Share protocol %s is not supported.") % requested_proto
            raise exception.ShareBackendException(msg=msg)

        # `share` is a Share
        msg = _("create_share {be} name={id} size={size}"
                " share_group_id={group}")
        LOG.debug(msg.format(
            be=self.backend_name, id=share['id'], size=share['size'],
            group=share['share_group_id']))

        extra_specs = share_types.get_extra_specs_from_share(share)
        data_isolated = extra_specs.get("cephfs:data_isolated", False)

        size = self._to_bytes(share['size'])

        # Create the CephFS volume
        cephfs_volume = self.volume_client.create_volume(
            cephfs_share_path(share), size=size, data_isolated=data_isolated,
            mode=self._cephfs_volume_mode)

        return self.protocol_helper.get_export_locations(share, cephfs_volume)

    def delete_share(self, context, share, share_server=None):
        extra_specs = share_types.get_extra_specs_from_share(share)
        data_isolated = extra_specs.get("cephfs:data_isolated", False)

        self.volume_client.delete_volume(cephfs_share_path(share),
                                         data_isolated=data_isolated)
        self.volume_client.purge_volume(cephfs_share_path(share),
                                        data_isolated=data_isolated)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        return self.protocol_helper.update_access(
            context, share, access_rules, add_rules, delete_rules,
            share_server=share_server)

    def ensure_share(self, context, share, share_server=None):
        # Creation is idempotent
        return self.create_share(context, share, share_server)

    def extend_share(self, share, new_size, share_server=None):
        LOG.debug("extend_share {id} {size}".format(
            id=share['id'], size=new_size))
        self.volume_client.set_max_bytes(cephfs_share_path(share),
                                         self._to_bytes(new_size))

    def shrink_share(self, share, new_size, share_server=None):
        LOG.debug("shrink_share {id} {size}".format(
            id=share['id'], size=new_size))
        new_bytes = self._to_bytes(new_size)
        used = self.volume_client.get_used_bytes(cephfs_share_path(share))
        if used > new_bytes:
            # While in fact we can "shrink" our volumes to less than their
            # used bytes (it's just a quota), raise error anyway to avoid
            # confusing API consumers that might depend on typical shrink
            # behaviour.
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

        self.volume_client.set_max_bytes(cephfs_share_path(share), new_bytes)

    def create_snapshot(self, context, snapshot, share_server=None):
        self.volume_client.create_snapshot_volume(
            cephfs_share_path(snapshot['share']),
            '_'.join([snapshot['snapshot_id'], snapshot['id']]),
            mode=self._cephfs_volume_mode)

    def delete_snapshot(self, context, snapshot, share_server=None):
        self.volume_client.destroy_snapshot_volume(
            cephfs_share_path(snapshot['share']),
            '_'.join([snapshot['snapshot_id'], snapshot['id']]))

    def create_share_group(self, context, sg_dict, share_server=None):
        self.volume_client.create_group(sg_dict['id'],
                                        mode=self._cephfs_volume_mode)

    def delete_share_group(self, context, sg_dict, share_server=None):
        self.volume_client.destroy_group(sg_dict['id'])

    def delete_share_group_snapshot(self, context, snap_dict,
                                    share_server=None):
        self.volume_client.destroy_snapshot_group(
            snap_dict['share_group_id'],
            snap_dict['id'])

        return None, []

    def create_share_group_snapshot(self, context, snap_dict,
                                    share_server=None):
        self.volume_client.create_snapshot_group(
            snap_dict['share_group_id'],
            snap_dict['id'],
            mode=self._cephfs_volume_mode)

        return None, []

    def __del__(self):
        if self._volume_client:
            self._volume_client.disconnect()
            self._volume_client = None


class NativeProtocolHelper(ganesha.NASHelperBase):
    """Helper class for native CephFS protocol"""

    supported_access_types = (CEPHX_ACCESS_TYPE, )
    supported_access_levels = (constants.ACCESS_LEVEL_RW,
                               constants.ACCESS_LEVEL_RO)

    def __init__(self, execute, config, **kwargs):
        self.volume_client = kwargs.pop('ceph_vol_client')
        super(NativeProtocolHelper, self).__init__(execute, config,
                                                   **kwargs)

    def _init_helper(self):
        pass

    def get_export_locations(self, share, cephfs_volume):
        # To mount this you need to know the mon IPs and the path to the volume
        mon_addrs = self.volume_client.get_mon_addrs()

        export_location = "{addrs}:{path}".format(
            addrs=",".join(mon_addrs),
            path=cephfs_volume['mount_path'])

        LOG.info("Calculated export location for share %(id)s: %(loc)s",
                 {"id": share['id'], "loc": export_location})

        return {
            'path': export_location,
            'is_admin_only': False,
            'metadata': {},
        }

    def _allow_access(self, context, share, access, share_server=None):
        if access['access_type'] != CEPHX_ACCESS_TYPE:
            raise exception.InvalidShareAccess(
                reason=_("Only 'cephx' access type allowed."))

        ceph_auth_id = access['access_to']

        # We need to check here rather than the API or Manila Client to see
        # if the ceph_auth_id is the same as the one specified for Manila's
        # usage. This is due to the fact that the API and the Manila client
        # cannot read the contents of the Manila configuration file. If it
        # is the same, we need to error out.
        if ceph_auth_id == CONF.cephfs_auth_id:
            error_message = (_('Ceph authentication ID %s must be different '
                             'than the one the Manila service uses.') %
                             ceph_auth_id)
            raise exception.InvalidInput(message=error_message)

        if not getattr(self.volume_client, 'version', None):
            if access['access_level'] == constants.ACCESS_LEVEL_RO:
                LOG.error("Need python-cephfs package version 10.2.3 or "
                          "greater to enable read-only access.")
                raise exception.InvalidShareAccessLevel(
                    level=constants.ACCESS_LEVEL_RO)

            auth_result = self.volume_client.authorize(
                cephfs_share_path(share), ceph_auth_id)
        else:
            readonly = access['access_level'] == constants.ACCESS_LEVEL_RO
            auth_result = self.volume_client.authorize(
                cephfs_share_path(share), ceph_auth_id, readonly=readonly,
                tenant_id=share['project_id'])

        return auth_result['auth_key']

    def _deny_access(self, context, share, access, share_server=None):
        if access['access_type'] != CEPHX_ACCESS_TYPE:
            LOG.warning("Invalid access type '%(type)s', "
                        "ignoring in deny.",
                        {"type": access['access_type']})
            return

        self.volume_client.deauthorize(cephfs_share_path(share),
                                       access['access_to'])
        self.volume_client.evict(
            access['access_to'],
            volume_path=cephfs_share_path(share))

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        access_keys = {}

        if not (add_rules or delete_rules):  # recovery/maintenance mode
            add_rules = access_rules

            existing_auths = None

            # The unversioned volume client cannot fetch from the Ceph backend,
            # the list of auth IDs that have share access.
            if getattr(self.volume_client, 'version', None):
                existing_auths = self.volume_client.get_authorized_ids(
                    cephfs_share_path(share))

            if existing_auths:
                existing_auth_ids = set(
                    [auth[0] for auth in existing_auths])
                want_auth_ids = set(
                    [rule['access_to'] for rule in add_rules])
                delete_auth_ids = existing_auth_ids.difference(
                    want_auth_ids)
                for delete_auth_id in delete_auth_ids:
                    delete_rules.append(
                        {
                            'access_to': delete_auth_id,
                            'access_type': CEPHX_ACCESS_TYPE,
                        })

        # During recovery mode, re-authorize share access for auth IDs that
        # were already granted access by the backend. Do this to fetch their
        # access keys and ensure that after recovery, manila and the Ceph
        # backend are in sync.
        for rule in add_rules:
            access_key = self._allow_access(context, share, rule)
            access_keys.update({rule['access_id']: {'access_key': access_key}})

        for rule in delete_rules:
            self._deny_access(context, share, rule)

        return access_keys


class NFSProtocolHelper(ganesha.GaneshaNASHelper2):

    shared_data = {}
    supported_protocols = ('NFS',)

    def __init__(self, execute, config_object, **kwargs):
        if config_object.cephfs_ganesha_server_is_remote:
            execute = ganesha_utils.SSHExecutor(
                config_object.cephfs_ganesha_server_ip, 22, None,
                config_object.cephfs_ganesha_server_username,
                password=config_object.cephfs_ganesha_server_password,
                privatekey=config_object.cephfs_ganesha_path_to_private_key)
        else:
            execute = ganesha_utils.RootExecutor(execute)

        self.ganesha_host = config_object.cephfs_ganesha_server_ip
        if not self.ganesha_host:
            self.ganesha_host = socket.gethostname()
            LOG.info("NFS-Ganesha server's location defaulted to driver's "
                     "hostname: %s", self.ganesha_host)

        super(NFSProtocolHelper, self).__init__(execute, config_object,
                                                **kwargs)

        if not hasattr(self, 'ceph_vol_client'):
            self.ceph_vol_client = kwargs.pop('ceph_vol_client')

    def get_export_locations(self, share, cephfs_volume):
        export_location = "{server_address}:{path}".format(
            server_address=self.ganesha_host,
            path=cephfs_volume['mount_path'])

        LOG.info("Calculated export location for share %(id)s: %(loc)s",
                 {"id": share['id'], "loc": export_location})

        return {
            'path': export_location,
            'is_admin_only': False,
            'metadata': {},
        }

    def _default_config_hook(self):
        """Callback to provide default export block."""
        dconf = super(NFSProtocolHelper, self)._default_config_hook()
        conf_dir = ganesha_utils.path_from(__file__, "conf")
        ganesha_utils.patch(dconf, self._load_conf_dir(conf_dir))
        return dconf

    def _fsal_hook(self, base, share, access):
        """Callback to create FSAL subblock."""
        ceph_auth_id = ''.join(['ganesha-', share['id']])
        auth_result = self.ceph_vol_client.authorize(
            cephfs_share_path(share), ceph_auth_id, readonly=False,
            tenant_id=share['project_id'])
        # Restrict Ganesha server's access to only the CephFS subtree or path,
        # corresponding to the manila share, that is to be exported by making
        # Ganesha use Ceph auth IDs with path restricted capabilities to
        # communicate with CephFS.
        return {
            'Name': 'Ceph',
            'User_Id': ceph_auth_id,
            'Secret_Access_Key': auth_result['auth_key']
        }

    def _cleanup_fsal_hook(self, base, share, access):
        """Callback for FSAL specific cleanup after removing an export."""
        ceph_auth_id = ''.join(['ganesha-', share['id']])
        self.ceph_vol_client.deauthorize(cephfs_share_path(share),
                                         ceph_auth_id)

    def _get_export_path(self, share):
        """Callback to provide export path."""
        volume_path = cephfs_share_path(share)
        return self.ceph_vol_client._get_path(volume_path)

    def _get_export_pseudo_path(self, share):
        """Callback to provide pseudo path."""
        volume_path = cephfs_share_path(share)
        return self.ceph_vol_client._get_path(volume_path)
