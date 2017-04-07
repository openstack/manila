# Copyright (c) 2016 QNAP Systems, Inc.
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
Share driver for QNAP Storage.
This driver supports QNAP Storage for NFS.
"""
import re

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila import share
from manila.share import driver
from manila.share.drivers.qnap import api
from manila import utils

LOG = logging.getLogger(__name__)

qnap_manila_opts = [
    cfg.StrOpt('qnap_management_url',
               required=True,
               help='The URL to manage QNAP Storage.'),
    cfg.HostAddressOpt('qnap_share_ip',
                       required=True,
                       help='NAS share IP for mounting shares.'),
    cfg.StrOpt('qnap_nas_login',
               required=True,
               help='Username for QNAP storage.'),
    cfg.StrOpt('qnap_nas_password',
               required=True,
               secret=True,
               help='Password for QNAP storage.'),
    cfg.StrOpt('qnap_poolname',
               required=True,
               help='Pool within which QNAP shares must be created.'),
]

CONF = cfg.CONF
CONF.register_opts(qnap_manila_opts)


class QnapShareDriver(driver.ShareDriver):
    """OpenStack driver to enable QNAP Storage.

    Version history:
        1.0.0 - Initial driver (Only NFS)
    """

    DRIVER_VERSION = '1.0.0'

    def __init__(self, *args, **kwargs):
        """Initialize QnapShareDriver."""
        super(QnapShareDriver, self).__init__(False, *args, **kwargs)
        self.private_storage = kwargs.get('private_storage')
        self.api_executor = None
        self.group_stats = {}
        self.configuration.append_config_values(qnap_manila_opts)
        self.share_api = share.API()

    def do_setup(self, context):
        """Setup the QNAP Manila share driver."""
        self.ctxt = context
        LOG.debug('context: %s', context)

        # Setup API Executor
        try:
            self.api_executor = self._create_api_executor()
        except Exception:
            LOG.exception('Failed to create HTTP client. Check IP '
                          'address, port, username, password and make '
                          'sure the array version is compatible.')
            raise

    def check_for_setup_error(self):
        """Check the status of setup."""
        if self.api_executor is None:
            msg = _("Failed to instantiate API client to communicate with "
                    "QNAP storage systems.")
            raise exception.ShareBackendException(msg=msg)

    def _create_api_executor(self):
        """Create API executor by NAS model."""
        """LOG.debug('CONF.qnap_nas_login=%(conf)s',
                  {'conf': CONF.qnap_nas_login})
        LOG.debug('self.configuration.qnap_nas_login=%(conf)s',
                  {'conf': self.configuration.qnap_nas_login})"""
        self.api_executor = api.QnapAPIExecutor(
            username=self.configuration.qnap_nas_login,
            password=self.configuration.qnap_nas_password,
            management_url=self.configuration.qnap_management_url)

        display_model_name, internal_model_name, fw_version = (
            self.api_executor.get_basic_info(
                self.configuration.qnap_management_url))

        pattern = re.compile(r"^([A-Z]+)-?[A-Z]{0,2}(\d+)\d{2}(U|[a-z]*)")
        matches = pattern.match(display_model_name)

        if not matches:
            return None
        model_type = matches.group(1)

        ts_model_types = (
            "TS", "SS", "IS", "TVS", "TDS", "TBS"
        )
        tes_model_types = (
            "TES",
        )
        es_model_types = (
            "ES",
        )

        if model_type in ts_model_types:
            if (fw_version.startswith("4.2") or fw_version.startswith("4.3")):
                LOG.debug('Create TS API Executor')
                # modify the pool name to pool index
                self.configuration.qnap_poolname = (
                    self._get_ts_model_pool_id(
                        self.configuration.qnap_poolname))

                return api.QnapAPIExecutorTS(
                    username=self.configuration.qnap_nas_login,
                    password=self.configuration.qnap_nas_password,
                    management_url=self.configuration.qnap_management_url)
        elif model_type in tes_model_types:
            if 'TS' in internal_model_name:
                if (fw_version.startswith("4.2") or
                        fw_version.startswith("4.3")):
                    LOG.debug('Create TS API Executor')
                    # modify the pool name to pool index
                    self.configuration.qnap_poolname = (
                        self._get_ts_model_pool_id(
                            self.configuration.qnap_poolname))
                    return api.QnapAPIExecutorTS(
                        username=self.configuration.qnap_nas_login,
                        password=self.configuration.qnap_nas_password,
                        management_url=self.configuration.qnap_management_url)

            if (fw_version.startswith("1.1.2") or
                    fw_version.startswith("1.1.3")):
                LOG.debug('Create ES API Executor')
                return api.QnapAPIExecutor(
                    username=self.configuration.qnap_nas_login,
                    password=self.configuration.qnap_nas_password,
                    management_url=self.configuration.qnap_management_url)
        elif model_type in es_model_types:
            if (fw_version.startswith("1.1.2") or
                    fw_version.startswith("1.1.3")):
                LOG.debug('Create ES API Executor')
                return api.QnapAPIExecutor(
                    username=self.configuration.qnap_nas_login,
                    password=self.configuration.qnap_nas_password,
                    management_url=self.configuration.qnap_management_url)

        msg = _('QNAP Storage model is not supported by this driver.')
        raise exception.ShareBackendException(msg=msg)

    def _get_ts_model_pool_id(self, pool_name):
        """Modify the pool name to pool index."""
        pattern = re.compile(r"^(\d+)+|^Storage Pool (\d+)+")
        matches = pattern.match(pool_name)
        if matches.group(1):
            return matches.group(1)
        else:
            return matches.group(2)

    @utils.synchronized('qnap-gen_name')
    def _gen_random_name(self, type):
        if type == 'share':
            infix = "shr-"
        elif type == 'snapshot':
            infix = "snp-"
        elif type == 'host':
            infix = "hst-"
        else:
            infix = ""
        return ("manila-%(ifx)s%(time)s" %
                {'ifx': infix,
                 'time': timeutils.utcnow().strftime('%Y%m%d%H%M%S%f')})

    def _get_location_path(self, share_name, share_proto, ip):
        if share_proto == 'NFS':
            created_share = self.api_executor.get_share_info(
                self.configuration.qnap_poolname,
                vol_label=share_name)
            vol_no = created_share.find('vol_no').text
            vol = self.api_executor.get_specific_volinfo(vol_no)
            vol_mount_path = vol.find('vol_mount_path').text

            location = '%s:%s' % (ip, vol_mount_path)
        else:
            msg = _('Invalid NAS protocol: %s') % share_proto
            raise exception.InvalidInput(reason=msg)

        export_location = {
            'path': location,
            'is_admin_only': False,
        }
        return export_location

    def _update_share_stats(self):
        """Get latest share stats."""
        backend_name = (self.configuration.safe_get(
                        'share_backend_name') or
                        self.__class__.__name__)
        LOG.debug('backend_name=%(backend_name)s',
                  {'backend_name': backend_name})

        selected_pool = self.api_executor.get_specific_poolinfo(
            self.configuration.qnap_poolname)
        total_capacity_gb = (int(selected_pool.find('capacity_bytes').text) /
                             units.Gi)
        LOG.debug('total_capacity_gb: %s GB', total_capacity_gb)
        free_capacity_gb = (int(selected_pool.find('freesize_bytes').text) /
                            units.Gi)
        LOG.debug('free_capacity_gb: %s GB', free_capacity_gb)
        alloc_capacity_gb = (int(selected_pool.find('allocated_bytes').text) /
                             units.Gi)
        LOG.debug('allocated_capacity_gb: %s GB', alloc_capacity_gb)

        reserved_percentage = self.configuration.safe_get(
            'reserved_share_percentage')

        # single pool now, need support multiple pools in the future
        single_pool = {
            "pool_name": self.configuration.qnap_poolname,
            "total_capacity_gb": total_capacity_gb,
            "free_capacity_gb": free_capacity_gb,
            "allocated_capacity_gb": alloc_capacity_gb,
            "reserved_percentage": reserved_percentage,
            "qos": False,
        }

        data = {
            "share_backend_name": backend_name,
            "vendor_name": "QNAP",
            "driver_version": self.DRIVER_VERSION,
            "storage_protocol": "NFS",
            "snapshot_support": True,
            "create_share_from_snapshot_support": True,
            "driver_handles_share_servers": self.configuration.safe_get(
                'driver_handles_share_servers'),
            'pools': [single_pool],
        }
        super(self.__class__, self)._update_share_stats(data)

    @utils.retry(exception=exception.ShareBackendException,
                 interval=3,
                 retries=200)
    def create_share(self, context, share, share_server=None):
        """Create a new share."""
        LOG.debug('share: %s', share.__dict__)

        share_proto = share['share_proto']

        # User could create two shares with the same name on horizon.
        # Therefore, we should not use displayname to create shares on NAS.
        create_share_name = self._gen_random_name("share")
        # If share name exists, need to change to another name.
        created_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_label=create_share_name)

        if created_share is not None:
            msg = _("Failed to create an unused share name.")
            raise exception.ShareBackendException(msg=msg)

        create_volID = self.api_executor.create_share(
            share,
            self.configuration.qnap_poolname,
            create_share_name,
            share_proto)

        # Use private_storage to record volume ID and Name created in the NAS.
        _metadata = {'volID': create_volID, 'volName': create_share_name}
        self.private_storage.update(share['id'], _metadata)

        return self._get_location_path(create_share_name,
                                       share['share_proto'],
                                       self.configuration.qnap_share_ip)

    def delete_share(self, context, share, share_server=None):
        """Delete the specified share."""
        # Use private_storage to retreive volume ID created in the NAS.
        volID = self.private_storage.get(share['id'], 'volID')
        if not volID:
            LOG.warning('volID for Share %s does not exist', share['id'])
            return
        LOG.debug('volID: %s', volID)

        del_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_no=volID)
        if del_share is None:
            LOG.warning('Share %s does not exist', share['id'])
            return

        vol_no = del_share.find('vol_no').text

        self.api_executor.delete_share(vol_no)
        self.private_storage.delete(share['id'])

    def extend_share(self, share, new_size, share_server=None):
        """Extend an existing share."""
        LOG.debug('Entering extend_share share=%(share)s '
                  'new_size=%(size)s',
                  {'share': share['display_name'], 'size': new_size})

        # Use private_storage to retrieve volume Name created in the NAS.
        volName = self.private_storage.get(share['id'], 'volName')
        if not volName:
            LOG.debug('Share %s does not exist', share['id'])
            raise exception.ShareResourceNotFound(share_id=share['id'])
        LOG.debug('volName: %s', volName)

        share_dict = {
            "sharename": volName,
            "old_sharename": volName,
            "new_size": new_size,
        }
        self.api_executor.edit_share(share_dict)

    @utils.retry(exception=exception.ShareBackendException,
                 interval=3,
                 retries=200)
    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        LOG.debug('snapshot[share][share_id]: %s',
                  snapshot['share']['share_id'])
        LOG.debug('snapshot id: %s', snapshot['id'])

        # Use private_storage to retrieve volume ID created in the NAS.
        volID = self.private_storage.get(snapshot['share']['id'], 'volID')
        if not volID:
            LOG.warning(
                'volID for Share %s does not exist',
                snapshot['share']['id'])
            raise exception.ShareResourceNotFound(
                share_id=snapshot['share']['id'])
        LOG.debug('volID: %s', volID)

        # User could create two snapshot with the same name on horizon.
        # Therefore, we should not use displayname to create snapshot on NAS.

        # if snapshot exist, need to change another
        create_snapshot_name = self._gen_random_name("snapshot")
        LOG.debug('create_snapshot_name: %s', create_snapshot_name)
        check_snapshot = self.api_executor.get_snapshot_info(
            volID=volID, snapshot_name=create_snapshot_name)
        if check_snapshot is not None:
            msg = _("Failed to create an unused snapshot name.")
            raise exception.ShareBackendException(msg=msg)

        LOG.debug('create_snapshot_name: %s', create_snapshot_name)
        self.api_executor.create_snapshot_api(volID, create_snapshot_name)

        snapshot_id = ""
        created_snapshot = self.api_executor.get_snapshot_info(
            volID=volID, snapshot_name=create_snapshot_name)
        if created_snapshot is not None:
            snapshot_id = created_snapshot.find('snapshot_id').text
        else:
            msg = _("Failed to get snapshot information.")
            raise exception.ShareBackendException(msg=msg)

        LOG.debug('created_snapshot: %s', created_snapshot)
        LOG.debug('snapshot_id: %s', snapshot_id)

        # Use private_storage to record data instead of metadata.
        _metadata = {'snapshot_id': snapshot_id}
        self.private_storage.update(snapshot['id'], _metadata)

        # Test to get value from private_storage.
        snapshot_id = self.private_storage.get(snapshot['id'], 'snapshot_id')
        LOG.debug('snapshot_id: %s', snapshot_id)

        return {'provider_location': snapshot_id}

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug('Entering delete_snapshot. The deleted snapshot=%(snap)s',
                  {'snap': snapshot['id']})

        snapshot_id = (snapshot.get('provider_location') or
                       self.private_storage.get(snapshot['id'], 'snapshot_id'))
        if not snapshot_id:
            LOG.warning('Snapshot %s does not exist', snapshot['id'])
            return
        LOG.debug('snapshot_id: %s', snapshot_id)

        self.api_executor.delete_snapshot_api(snapshot_id)
        self.private_storage.delete(snapshot['id'])

    @utils.retry(exception=exception.ShareBackendException,
                 interval=3,
                 retries=200)
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from a snapshot."""
        LOG.debug('Entering create_share_from_snapshot. The source '
                  'snapshot=%(snap)s. The created share=%(share)s',
                  {'snap': snapshot['id'], 'share': share['id']})

        snapshot_id = (snapshot.get('provider_location') or
                       self.private_storage.get(snapshot['id'], 'snapshot_id'))
        if not snapshot_id:
            LOG.warning('Snapshot %s does not exist', snapshot['id'])
            raise exception.SnapshotResourceNotFound(name=snapshot['id'])
        LOG.debug('snapshot_id: %s', snapshot_id)

        create_share_name = self._gen_random_name("share")
        # if sharename exist, need to change another
        created_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_label=create_share_name)

        if created_share is not None:
            msg = _("Failed to create an unused share name.")
            raise exception.ShareBackendException(msg=msg)

        self.api_executor.clone_snapshot(snapshot_id, create_share_name)

        create_volID = ""
        created_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_label=create_share_name)
        if created_share.find('vol_no') is not None:
            create_volID = created_share.find('vol_no').text
        else:
            msg = _("Failed to clone a snapshot in time.")
            raise exception.ShareBackendException(msg=msg)

        snap_share = self.share_api.get(context,
                                        snapshot['share_instance']['share_id'])
        LOG.debug('snap_share[size]: %s', snap_share['size'])

        if (share['size'] > snap_share['size']):
            share_dict = {'sharename': create_share_name,
                          'old_sharename': create_share_name,
                          'new_size': share['size']}
            self.api_executor.edit_share(share_dict)

        # Use private_storage to record volume ID and Name created in the NAS.
        _metadata = {
            'volID': create_volID,
            'volName': create_share_name,
        }
        self.private_storage.update(share['id'], _metadata)

        # Test to get value from private_storage.
        volName = self.private_storage.get(share['id'], 'volName')
        LOG.debug('volName: %s', volName)

        return self._get_location_path(create_share_name,
                                       share['share_proto'],
                                       self.configuration.qnap_share_ip)

    def _get_manila_hostIPv4s(self, hostlist):
        host_dict_IPs = []
        if hostlist is None:
            return host_dict_IPs
        for host in hostlist:
            # Check host alias name with prefix "manila-hst-" to verify this
            # host is created/managed by Manila or not.
            if (re.match("^manila-hst-[0-9]+$", host.find('name').text)
               is not None):
                LOG.debug('host netaddrs text: %s', host.find('netaddrs').text)
                if host.find('netaddrs').text is not None:
                    # Because Manila supports only IPv4 now, check "netaddrs"
                    # have "ipv4" tag to verify this host is created/managed
                    # by Manila or not.
                    if host.find('netaddrs/ipv4').text is not None:
                        host_dict = {
                            'index': host.find('index').text,
                            'hostid': host.find('hostid').text,
                            'name': host.find('name').text,
                            'netaddrs': host.find('netaddrs').find('ipv4').text
                        }
                        host_dict_IPs.append(host_dict)
        return host_dict_IPs

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        if not (add_rules or delete_rules):
            volName = self.private_storage.get(share['id'], 'volName')
            LOG.debug('volName: %s', volName)

            if volName is None:
                LOG.debug('Share %s does not exist', share['id'])
                raise exception.ShareResourceNotFound(share_id=share['id'])

            # Clear all current ACLs
            self.api_executor.set_nfs_access(volName, 2, "all")

            # Add each one through all rules.
            for access in access_rules:
                self._allow_access(context, share, access, share_server)
        else:
            # Adding/Deleting specific rules
            for access in delete_rules:
                self._deny_access(context, share, access, share_server)
            for access in add_rules:
                self._allow_access(context, share, access, share_server)

    def _allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        share_proto = share['share_proto']
        access_type = access['access_type']
        access_level = access['access_level']
        access_to = access['access_to']

        self._check_share_access(share_proto, access_type)

        hostlist = self.api_executor.get_host_list()
        host_dict_IPs = self._get_manila_hostIPv4s(hostlist)
        LOG.debug('host_dict_IPs: %s', host_dict_IPs)
        if len(host_dict_IPs) == 0:
            host_name = self._gen_random_name("host")
            self.api_executor.add_host(host_name, access_to)
        else:
            for host in host_dict_IPs:
                LOG.debug('host[netaddrs]: %s', host['netaddrs'])
                LOG.debug('access_to: %s', access_to)
                if host['netaddrs'] == access_to:
                    LOG.debug('in match ip')
                    host_name = host['name']
                    break
                if host is host_dict_IPs[-1]:
                    host_name = self._gen_random_name("host")
                    self.api_executor.add_host(host_name, access_to)

        volName = self.private_storage.get(share['id'], 'volName')
        LOG.debug('volName: %(volName)s for share: %(share)s',
                  {'volName': volName, 'share': share['id']})

        LOG.debug('access_level: %(access)s for share: %(share)s',
                  {'access': access_level, 'share': share['id']})
        LOG.debug('host_name: %(host)s for share: %(share)s',
                  {'host': host_name, 'share': share['id']})
        if access_level == constants.ACCESS_LEVEL_RO:
            self.api_executor.set_nfs_access(volName, 1, host_name)
        elif access_level == constants.ACCESS_LEVEL_RW:
            self.api_executor.set_nfs_access(volName, 0, host_name)

    def _deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        share_proto = share['share_proto']
        access_type = access['access_type']
        access_to = access['access_to']

        try:
            self._check_share_access(share_proto, access_type)
        except exception.InvalidShareAccess:
            LOG.warning('The denied rule is invalid and does not exist.')
            return

        hostlist = self.api_executor.get_host_list()
        host_dict_IPs = self._get_manila_hostIPv4s(hostlist)
        LOG.debug('host_dict_IPs: %s', host_dict_IPs)
        if len(host_dict_IPs) == 0:
            return
        else:
            for host in host_dict_IPs:
                if (host['netaddrs'] == access_to):
                    host_name = host['name']
                    break
                if (host is host_dict_IPs[-1]):
                    return

        volName = self.private_storage.get(share['id'], 'volName')
        LOG.debug('volName: %s', volName)

        self.api_executor.set_nfs_access(volName, 2, host_name)

    def _check_share_access(self, share_proto, access_type):
        if share_proto == 'NFS' and access_type != 'ip':
            reason = _('Only "ip" access type is allowed for '
                       'NFS shares.')
            LOG.warning(reason)
            raise exception.InvalidShareAccess(reason=reason)
        elif share_proto != 'NFS':
            reason = _('Invalid NAS protocol: %s') % share_proto
            raise exception.InvalidShareAccess(reason=reason)

    def manage_existing(self, share, driver_options):
        """Manages a share that exists on backend."""
        if share['share_proto'].lower() == 'nfs':
            # 10.0.0.1:/share/example
            LOG.info("Share %(shr_path)s will be managed with ID"
                     "%(shr_id)s.",
                     {'shr_path': share['export_locations'][0]['path'],
                      'shr_id': share['id']})

            old_path_info = share['export_locations'][0]['path'].split(
                ':/share/')

            if len(old_path_info) == 2:
                ip = old_path_info[0]
                share_name = old_path_info[1]
            else:
                msg = _("Incorrect path. It should have the following format: "
                        "IP:/share/share_name.")
                raise exception.ShareBackendException(msg=msg)
        else:
            msg = _('Invalid NAS protocol: %s') % share['share_proto']
            raise exception.InvalidInput(reason=msg)

        if ip != self.configuration.qnap_share_ip:
            msg = _("The NAS IP %(ip)s is not configured.") % {'ip': ip}
            raise exception.ShareBackendException(msg=msg)

        existing_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_label=share_name)
        if existing_share is None:
            msg = _("The share %s trying to be managed was not found on "
                    "backend.") % share['id']
            raise exception.ManageInvalidShare(reason=msg)

        _metadata = {}
        vol_no = existing_share.find('vol_no').text
        _metadata['volID'] = vol_no
        _metadata['volName'] = share_name
        self.private_storage.update(share['id'], _metadata)

        # Test to get value from private_storage.
        volID = self.private_storage.get(share['id'], 'volID')
        LOG.debug('volID: %s', volID)
        volName = self.private_storage.get(share['id'], 'volName')
        LOG.debug('volName: %s', volName)

        LOG.info("Share %(shr_path)s was successfully managed with ID "
                 "%(shr_id)s.",
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})

        vol = self.api_executor.get_specific_volinfo(vol_no)
        vol_size_gb = int(vol.find('size').text) / units.Gi
        export_locations = self._get_location_path(
            share_name,
            share['share_proto'],
            self.configuration.qnap_share_ip)

        return {'size': vol_size_gb, 'export_locations': export_locations}

    def unmanage(self, share):
        """Remove the specified share from Manila management."""
        self.private_storage.delete(share['id'])

    def manage_existing_snapshot(self, snapshot, driver_options):
        """Manage existing share snapshot with manila."""
        volID = self.private_storage.get(snapshot['share']['id'], 'volID')
        LOG.debug('volID: %s', volID)

        existing_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_no=volID)

        if existing_share is None:
            msg = _("The share id %s was not found on backend.") % volID
            LOG.error(msg)
            raise exception.ShareNotFound(reason=msg)

        snapshot_id = snapshot.get('provider_location')
        snapshot_id_info = snapshot_id.split('@')

        if len(snapshot_id_info) == 2:
            share_name = snapshot_id_info[0]
        else:
            msg = _("Incorrect provider_location format. It should have the "
                    "following format: share_name@snapshot_name.")
            LOG.error(msg)
            raise exception.InvalidParameterValue(reason=msg)

        if share_name != existing_share.find('vol_label').text:
            msg = (_("The assigned share %(share_name)s was not matched "
                   "%(vol_label)s on backend.") %
                   {'share_name': share_name,
                    'vol_label': existing_share.find('vol_label').text})
            LOG.error(msg)
            raise exception.ShareNotFound(reason=msg)

        _metadata = {
            'snapshot_id': snapshot_id,
        }
        self.private_storage.update(snapshot['id'], _metadata)

    def unmanage_snapshot(self, snapshot):
        """Remove the specified snapshot from Manila management."""
        self.private_storage.delete(snapshot['id'])
