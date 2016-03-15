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


from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share import driver
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


LOG = log.getLogger(__name__)

cephfs_native_opts = [
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
]


CONF = cfg.CONF
CONF.register_opts(cephfs_native_opts)


class CephFSNativeDriver(driver.ShareDriver,):
    """Driver for the Ceph Filsystem.

    This driver is 'native' in the sense that it exposes a CephFS filesystem
    for use directly by guests, with no intermediate layer like NFS.
    """

    supported_protocols = ('CEPHFS',)

    def __init__(self, *args, **kwargs):
        super(CephFSNativeDriver, self).__init__(False, *args, **kwargs)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'CephFS-Native'

        self._volume_client = None

        self.configuration.append_config_values(cephfs_native_opts)

    def _update_share_stats(self):
        stats = self.volume_client.rados.get_cluster_stats()

        total_capacity_gb = stats['kb'] * units.Mi
        free_capacity_gb = stats['kb_avail'] * units.Mi

        data = {
            'consistency_group_support': 'pool',
            'vendor_name': 'Ceph',
            'driver_version': '1.0',
            'share_backend_name': self.backend_name,
            'storage_protocol': "CEPHFS",
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
        super(CephFSNativeDriver, self)._update_share_stats(data)

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
        LOG.info(_LI("[%(be)s}] Ceph client found, connecting..."),
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
            LOG.info(_LI("[%(be)s] Ceph client connection complete."),
                     {"be": self.backend_name})

        return self._volume_client

    def _share_path(self, share):
        """Get VolumePath from Share."""
        return ceph_volume_client.VolumePath(
            share['consistency_group_id'], share['id'])

    def create_share(self, context, share, share_server=None):
        """Create a CephFS volume.

        :param context: A RequestContext.
        :param share: A Share.
        :param share_server: Always None for CephFS native.
        :return: The export locations dictionary.
        """

        # `share` is a Share
        LOG.debug("create_share {be} name={id} size={size} cg_id={cg}".format(
            be=self.backend_name, id=share['id'], size=share['size'],
            cg=share['consistency_group_id']))

        extra_specs = share_types.get_extra_specs_from_share(share)
        data_isolated = extra_specs.get("cephfs:data_isolated", False)

        size = self._to_bytes(share['size'])

        # Create the CephFS volume
        volume = self.volume_client.create_volume(
            self._share_path(share), size=size, data_isolated=data_isolated)

        # To mount this you need to know the mon IPs and the path to the volume
        mon_addrs = self.volume_client.get_mon_addrs()

        export_location = "{addrs}:{path}".format(
            addrs=",".join(mon_addrs),
            path=volume['mount_path'])

        LOG.info(_LI("Calculated export location for share %(id)s: %(loc)s"),
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

        if access['access_level'] == constants.ACCESS_LEVEL_RO:
            raise exception.InvalidShareAccessLevel(
                level=constants.ACCESS_LEVEL_RO)

        ceph_auth_id = access['access_to']

        auth_result = self.volume_client.authorize(self._share_path(share),
                                                   ceph_auth_id)

        return auth_result['auth_key']

    def _deny_access(self, context, share, access, share_server=None):
        if access['access_type'] != CEPHX_ACCESS_TYPE:
            LOG.warning(_LW("Invalid access type '%(type)s', "
                            "ignoring in deny."),
                        {"type": access['access_type']})
            return

        self.volume_client.deauthorize(self._share_path(share),
                                       access['access_to'])
        self.volume_client.evict(access['access_to'])

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        # The interface to Ceph just provides add/remove methods, since it
        # was created at start of mitaka cycle when there was no requirement
        # to be able to list access rules or set them en masse.  Therefore
        # we implement update_access as best we can.  In future ceph's
        # interface should be extended to enable a full implementation
        # of update_access.

        for rule in add_rules:
            self._allow_access(context, share, rule)

        for rule in delete_rules:
            self._deny_access(context, share, rule)

        # This is where we would list all permitted clients and remove
        # those that are not in `access_rules` if the ceph interface
        # enabled it.
        if not (add_rules or delete_rules):
            for rule in access_rules:
                self._allow_access(context, share, rule)

    def delete_share(self, context, share, share_server=None):
        extra_specs = share_types.get_extra_specs_from_share(share)
        data_isolated = extra_specs.get("cephfs:data_isolated", False)

        self.volume_client.delete_volume(self._share_path(share),
                                         data_isolated=data_isolated)
        self.volume_client.purge_volume(self._share_path(share),
                                        data_isolated=data_isolated)

    def ensure_share(self, context, share, share_server=None):
        # Creation is idempotent
        return self.create_share(context, share, share_server)

    def extend_share(self, share, new_size, share_server=None):
        LOG.debug("extend_share {id} {size}".format(
            id=share['id'], size=new_size))
        self.volume_client.set_max_bytes(self._share_path(share),
                                         self._to_bytes(new_size))

    def shrink_share(self, share, new_size, share_server=None):
        LOG.debug("shrink_share {id} {size}".format(
            id=share['id'], size=new_size))
        new_bytes = self._to_bytes(new_size)
        used = self.volume_client.get_used_bytes(self._share_path(share))
        if used > new_bytes:
            # While in fact we can "shrink" our volumes to less than their
            # used bytes (it's just a quota), raise error anyway to avoid
            # confusing API consumers that might depend on typical shrink
            # behaviour.
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

        self.volume_client.set_max_bytes(self._share_path(share), new_bytes)

    def create_snapshot(self, context, snapshot, share_server=None):
        self.volume_client.create_snapshot_volume(
            self._share_path(snapshot['share']), snapshot['name'])

    def delete_snapshot(self, context, snapshot, share_server=None):
        self.volume_client.destroy_snapshot_volume(
            self._share_path(snapshot['share']), snapshot['name'])

    def create_consistency_group(self, context, cg_dict, share_server=None):
        self.volume_client.create_group(cg_dict['id'])

    def delete_consistency_group(self, context, cg_dict, share_server=None):
        self.volume_client.destroy_group(cg_dict['id'])

    def delete_cgsnapshot(self, context, snap_dict, share_server=None):
        self.volume_client.destroy_snapshot_group(
            snap_dict['consistency_group_id'],
            snap_dict['id'])

        return None, []

    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        self.volume_client.create_snapshot_group(
            snap_dict['consistency_group_id'],
            snap_dict['id'])

        return None, []

    def __del__(self):
        if self._volume_client:
            self._volume_client.disconnect()
            self._volume_client = None
