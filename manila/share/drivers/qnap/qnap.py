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
import datetime
import re
import time

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
from manila.share import share_types
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
        1.0.1 - Add support for QES fw 1.1.4.
        1.0.2 - Fix bug #1736370, QNAP Manila driver: Access rule setting is
                override by the another access rule.
        1.0.3 - Add supports for Thin Provisioning, SSD Cache, Deduplication
                and Compression.
        1.0.4 - Add support for QES fw 2.0.0.
    """

    DRIVER_VERSION = '1.0.4'

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
            elif "1.1.2" <= fw_version <= "2.0.9999":
                LOG.debug('Create ES API Executor')
                return api.QnapAPIExecutor(
                    username=self.configuration.qnap_nas_login,
                    password=self.configuration.qnap_nas_password,
                    management_url=self.configuration.qnap_management_url)
        elif model_type in es_model_types:
            if "1.1.2" <= fw_version <= "2.0.9999":
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

    def _gen_host_name(self, vol_name_timestamp, access_level):
        # host_name will be manila-{vol_name_timestamp}-ro or
        # manila-{vol_name_timestamp}-rw
        return 'manila-{}-{}'.format(vol_name_timestamp, access_level)

    def _get_timestamp_from_vol_name(self, vol_name):
        vol_name_split = vol_name.split('-')
        dt = datetime.datetime.strptime(vol_name_split[2], '%Y%m%d%H%M%S%f')
        return int(time.mktime(dt.timetuple()))

    def _get_location_path(self, share_name, share_proto, ip, vol_id):
        if share_proto == 'NFS':
            vol = self.api_executor.get_specific_volinfo(vol_id)
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
            "dedupe": [True, False],
            "compression": [True, False],
            "thin_provisioning": [True, False],
            "qnap_ssd_cache": [True, False]
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
                 retries=5)
    @utils.synchronized('qnap-create_share')
    def create_share(self, context, share, share_server=None):
        """Create a new share."""
        LOG.debug('share: %s', share.__dict__)
        extra_specs = share_types.get_extra_specs_from_share(share)
        LOG.debug('extra_specs: %s', extra_specs)
        qnap_thin_provision = share_types.parse_boolean_extra_spec(
            'thin_provisioning', extra_specs.get("thin_provisioning") or
            extra_specs.get('capabilities:thin_provisioning') or 'true')
        qnap_compression = share_types.parse_boolean_extra_spec(
            'compression', extra_specs.get("compression") or
            extra_specs.get('capabilities:compression') or 'true')
        qnap_deduplication = share_types.parse_boolean_extra_spec(
            'dedupe', extra_specs.get("dedupe") or
            extra_specs.get('capabilities:dedupe') or 'false')
        qnap_ssd_cache = share_types.parse_boolean_extra_spec(
            'qnap_ssd_cache', extra_specs.get("qnap_ssd_cache") or
            extra_specs.get("capabilities:qnap_ssd_cache") or 'false')
        LOG.debug('qnap_thin_provision: %(qnap_thin_provision)s '
                  'qnap_compression: %(qnap_compression)s '
                  'qnap_deduplication: %(qnap_deduplication)s '
                  'qnap_ssd_cache: %(qnap_ssd_cache)s',
                  {'qnap_thin_provision': qnap_thin_provision,
                   'qnap_compression': qnap_compression,
                   'qnap_deduplication': qnap_deduplication,
                   'qnap_ssd_cache': qnap_ssd_cache})

        share_proto = share['share_proto']

        # User could create two shares with the same name on horizon.
        # Therefore, we should not use displayname to create shares on NAS.
        create_share_name = self._gen_random_name("share")
        # If share name exists, need to change to another name.
        created_share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_label=create_share_name)
        LOG.debug('created_share: %s', created_share)
        if created_share is not None:
            msg = (_("The share name %s is used by other share on NAS.") %
                   create_share_name)
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        if (qnap_deduplication and not qnap_thin_provision):
            msg = _("Dedupe cannot be enabled without thin_provisioning.")
            LOG.debug('Dedupe cannot be enabled without thin_provisioning.')
            raise exception.InvalidExtraSpec(reason=msg)
        self.api_executor.create_share(
            share,
            self.configuration.qnap_poolname,
            create_share_name,
            share_proto,
            qnap_thin_provision=qnap_thin_provision,
            qnap_compression=qnap_compression,
            qnap_deduplication=qnap_deduplication,
            qnap_ssd_cache=qnap_ssd_cache)
        created_share = self._get_share_info(create_share_name)
        volID = created_share.find('vol_no').text
        # Use private_storage to record volume ID and Name created in the NAS.
        LOG.debug('volID: %(volID)s '
                  'volName: %(create_share_name)s',
                  {'volID': volID,
                   'create_share_name': create_share_name})
        _metadata = {'volID': volID,
                     'volName': create_share_name,
                     'thin_provision': qnap_thin_provision,
                     'compression': qnap_compression,
                     'deduplication': qnap_deduplication,
                     'ssd_cache': qnap_ssd_cache}
        self.private_storage.update(share['id'], _metadata)

        return self._get_location_path(create_share_name,
                                       share['share_proto'],
                                       self.configuration.qnap_share_ip,
                                       volID)

    @utils.retry(exception=exception.ShareBackendException,
                 interval=5, retries=5, backoff_rate=1)
    def _get_share_info(self, share_name):
        share = self.api_executor.get_share_info(
            self.configuration.qnap_poolname,
            vol_label=share_name)
        if share is None:
            msg = _("Fail to get share info of %s on NAS.") % share_name
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)
        else:
            return share

    @utils.synchronized('qnap-delete_share')
    def delete_share(self, context, share, share_server=None):
        """Delete the specified share."""
        # Use private_storage to retrieve volume ID created in the NAS.
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

    @utils.synchronized('qnap-extend_share')
    def extend_share(self, share, new_size, share_server=None):
        """Extend an existing share."""
        LOG.debug('Entering extend_share share_name=%(share_name)s '
                  'share_id=%(share_id)s '
                  'new_size=%(size)s',
                  {'share_name': share['display_name'],
                   'share_id': share['id'],
                   'size': new_size})

        # Use private_storage to retrieve volume Name created in the NAS.
        volName = self.private_storage.get(share['id'], 'volName')
        if not volName:
            LOG.debug('Share %s does not exist', share['id'])
            raise exception.ShareResourceNotFound(share_id=share['id'])
        LOG.debug('volName: %s', volName)
        thin_provision = self.private_storage.get(
            share['id'], 'thin_provision')
        compression = self.private_storage.get(share['id'], 'compression')
        deduplication = self.private_storage.get(share['id'], 'deduplication')
        ssd_cache = self.private_storage.get(share['id'], 'ssd_cache')
        LOG.debug('thin_provision: %(thin_provision)s '
                  'compression: %(compression)s '
                  'deduplication: %(deduplication)s '
                  'ssd_cache: %(ssd_cache)s',
                  {'thin_provision': thin_provision,
                   'compression': compression,
                   'deduplication': deduplication,
                   'ssd_cache': ssd_cache})
        share_dict = {
            'sharename': volName,
            'old_sharename': volName,
            'new_size': new_size,
            'thin_provision': thin_provision == 'True',
            'compression': compression == 'True',
            'deduplication': deduplication == 'True',
            'ssd_cache': ssd_cache == 'True',
            'share_proto': share['share_proto']
        }
        self.api_executor.edit_share(share_dict)

    @utils.retry(exception=exception.ShareBackendException,
                 interval=3,
                 retries=5)
    @utils.synchronized('qnap-create_snapshot')
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

    @utils.synchronized('qnap-delete_snapshot')
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
                 retries=5)
    @utils.synchronized('qnap-create_share_from_snapshot')
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
        if created_share is not None:
            create_volID = created_share.find('vol_no').text
            LOG.debug('create_volID: %s', create_volID)
        else:
            msg = _("Failed to clone a snapshot in time.")
            raise exception.ShareBackendException(msg=msg)

        snap_share = self.share_api.get(
            context, snapshot['share_instance']['share_id'])
        LOG.debug('snap_share[size]: %s', snap_share['size'])

        thin_provision = self.private_storage.get(
            snapshot['share_instance_id'], 'thin_provision')
        compression = self.private_storage.get(
            snapshot['share_instance_id'], 'compression')
        deduplication = self.private_storage.get(
            snapshot['share_instance_id'], 'deduplication')
        ssd_cache = self.private_storage.get(
            snapshot['share_instance_id'], 'ssd_cache')
        LOG.debug('thin_provision: %(thin_provision)s '
                  'compression: %(compression)s '
                  'deduplication: %(deduplication)s '
                  'ssd_cache: %(ssd_cache)s',
                  {'thin_provision': thin_provision,
                   'compression': compression,
                   'deduplication': deduplication,
                   'ssd_cache': ssd_cache})

        if (share['size'] > snap_share['size']):
            share_dict = {
                'sharename': create_share_name,
                'old_sharename': create_share_name,
                'new_size': share['size'],
                'thin_provision': thin_provision == 'True',
                'compression': compression == 'True',
                'deduplication': deduplication == 'True',
                'ssd_cache': ssd_cache == 'True',
                'share_proto': share['share_proto']
            }
            self.api_executor.edit_share(share_dict)

        # Use private_storage to record volume ID and Name created in the NAS.
        _metadata = {
            'volID': create_volID,
            'volName': create_share_name,
            'thin_provision': thin_provision,
            'compression': compression,
            'deduplication': deduplication,
            'ssd_cache': ssd_cache
        }
        self.private_storage.update(share['id'], _metadata)

        # Test to get value from private_storage.
        volName = self.private_storage.get(share['id'], 'volName')
        LOG.debug('volName: %s', volName)

        return self._get_location_path(create_share_name,
                                       share['share_proto'],
                                       self.configuration.qnap_share_ip,
                                       create_volID)

    def _get_vol_host(self, host_list, vol_name_timestamp):
        vol_host_list = []
        if host_list is None:
            return vol_host_list
        for host in host_list:
            # Check host alias name with prefix "manila-{vol_name_timestamp}"
            # to find the host of this manila share.
            LOG.debug('_get_vol_host name:%s', host.find('name').text)
            # Because driver supports only IPv4 now, check "netaddrs"
            # have "ipv4" tag to get address.
            if re.match("^manila-{}".format(vol_name_timestamp),
                        host.find('name').text):
                host_dict = {
                    'index': host.find('index').text,
                    'hostid': host.find('hostid').text,
                    'name': host.find('name').text,
                    'ipv4': [],
                }
                for ipv4 in host.findall('netaddrs/ipv4'):
                    host_dict['ipv4'].append(ipv4.text)
                vol_host_list.append(host_dict)
        LOG.debug('_get_vol_host vol_host_list:%s', vol_host_list)
        return vol_host_list

    @utils.synchronized('qnap-update_access')
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

            vol_name_timestamp = self._get_timestamp_from_vol_name(volName)
            host_list = self.api_executor.get_host_list()
            LOG.debug('host_list:%s', host_list)
            vol_host_list = self._get_vol_host(host_list, vol_name_timestamp)
            # If host already exist, delete the host
            if len(vol_host_list) > 0:
                for vol_host in vol_host_list:
                    self.api_executor.delete_host(vol_host['name'])

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
        LOG.debug('share_proto: %(share_proto)s '
                  'access_type: %(access_type)s'
                  'access_level: %(access_level)s'
                  'access_to: %(access_to)s',
                  {'share_proto': share_proto,
                   'access_type': access_type,
                   'access_level': access_level,
                   'access_to': access_to})

        self._check_share_access(share_proto, access_type)

        vol_name = self.private_storage.get(share['id'], 'volName')
        vol_name_timestamp = self._get_timestamp_from_vol_name(vol_name)
        host_name = self._gen_host_name(vol_name_timestamp, access_level)

        host_list = self.api_executor.get_host_list()
        LOG.debug('vol_name: %(vol_name)s '
                  'access_level: %(access_level)s '
                  'host_name: %(host_name)s '
                  'host_list: %(host_list)s ',
                  {'vol_name': vol_name,
                   'access_level': access_level,
                   'host_name': host_name,
                   'host_list': host_list})
        filter_host_list = self._get_vol_host(host_list, vol_name_timestamp)
        if len(filter_host_list) == 0:
            # if host does not exist, create a host for the share
            self.api_executor.add_host(host_name, access_to)
        elif (len(filter_host_list) == 1 and
              filter_host_list[0]['name'] == host_name):
            # if the host exist, and this host is for the same access right,
            # add ip to the host.
            ipv4_list = filter_host_list[0]['ipv4']
            if access_to not in ipv4_list:
                ipv4_list.append(access_to)
            LOG.debug('vol_host["ipv4"]: %s', filter_host_list[0]['ipv4'])
            LOG.debug('ipv4_list: %s', ipv4_list)
            self.api_executor.edit_host(host_name, ipv4_list)
        else:
            # Until now, share of QNAP NAS can only apply one access level for
            # all ips. "rw" for some ips and "ro" for else is not allowed.
            support_level = (constants.ACCESS_LEVEL_RW if
                             access_level == constants.ACCESS_LEVEL_RO
                             else constants.ACCESS_LEVEL_RO)
            reason = _('Share only supports one access '
                       'level: %s') % support_level
            LOG.error(reason)
            raise exception.InvalidShareAccess(reason=reason)
        access = 1 if access_level == constants.ACCESS_LEVEL_RO else 0
        self.api_executor.set_nfs_access(vol_name, access, host_name)

    def _deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        share_proto = share['share_proto']
        access_type = access['access_type']
        access_level = access['access_level']
        access_to = access['access_to']
        LOG.debug('share_proto: %(share_proto)s '
                  'access_type: %(access_type)s'
                  'access_level: %(access_level)s'
                  'access_to: %(access_to)s',
                  {'share_proto': share_proto,
                   'access_type': access_type,
                   'access_level': access_level,
                   'access_to': access_to})

        try:
            self._check_share_access(share_proto, access_type)
        except exception.InvalidShareAccess:
            LOG.warning('The denied rule is invalid and does not exist.')
            return

        vol_name = self.private_storage.get(share['id'], 'volName')
        vol_name_timestamp = self._get_timestamp_from_vol_name(vol_name)
        host_name = self._gen_host_name(vol_name_timestamp, access_level)
        host_list = self.api_executor.get_host_list()
        LOG.debug('vol_name: %(vol_name)s '
                  'access_level: %(access_level)s '
                  'host_name: %(host_name)s '
                  'host_list: %(host_list)s ',
                  {'vol_name': vol_name,
                   'access_level': access_level,
                   'host_name': host_name,
                   'host_list': host_list})
        filter_host_list = self._get_vol_host(host_list, vol_name_timestamp)
        # if share already have host, remove ip from host
        for vol_host in filter_host_list:
            if vol_host['name'] == host_name:
                ipv4_list = vol_host['ipv4']
                if access_to in ipv4_list:
                    ipv4_list.remove(access_to)
                LOG.debug('vol_host["ipv4"]: %s', vol_host['ipv4'])
                LOG.debug('ipv4_list: %s', ipv4_list)
                if len(ipv4_list) == 0:  # if list empty, remove the host
                    self.api_executor.set_nfs_access(
                        vol_name, 2, host_name)
                    self.api_executor.delete_host(host_name)
                else:
                    self.api_executor.edit_host(host_name, ipv4_list)
                break

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

        extra_specs = share_types.get_extra_specs_from_share(share)
        qnap_thin_provision = share_types.parse_boolean_extra_spec(
            'thin_provisioning', extra_specs.get("thin_provisioning") or
            extra_specs.get('capabilities:thin_provisioning') or 'true')
        qnap_compression = share_types.parse_boolean_extra_spec(
            'compression', extra_specs.get("compression") or
            extra_specs.get('capabilities:compression') or 'true')
        qnap_deduplication = share_types.parse_boolean_extra_spec(
            'dedupe', extra_specs.get("dedupe") or
            extra_specs.get('capabilities:dedupe') or 'false')
        qnap_ssd_cache = share_types.parse_boolean_extra_spec(
            'qnap_ssd_cache', extra_specs.get("qnap_ssd_cache") or
            extra_specs.get("capabilities:qnap_ssd_cache") or 'false')
        LOG.debug('qnap_thin_provision: %(qnap_thin_provision)s '
                  'qnap_compression: %(qnap_compression)s '
                  'qnap_deduplication: %(qnap_deduplication)s '
                  'qnap_ssd_cache: %(qnap_ssd_cache)s',
                  {'qnap_thin_provision': qnap_thin_provision,
                   'qnap_compression': qnap_compression,
                   'qnap_deduplication': qnap_deduplication,
                   'qnap_ssd_cache': qnap_ssd_cache})
        if (qnap_deduplication and not qnap_thin_provision):
            msg = _("Dedupe cannot be enabled without thin_provisioning.")
            LOG.debug('Dedupe cannot be enabled without thin_provisioning.')
            raise exception.InvalidExtraSpec(reason=msg)

        vol_no = existing_share.find('vol_no').text
        vol = self.api_executor.get_specific_volinfo(vol_no)
        vol_size_gb = int(vol.find('size').text) / units.Gi

        share_dict = {
            'sharename': share_name,
            'old_sharename': share_name,
            'new_size': vol_size_gb,
            'thin_provision': qnap_thin_provision,
            'compression': qnap_compression,
            'deduplication': qnap_deduplication,
            'ssd_cache': qnap_ssd_cache,
            'share_proto': share['share_proto']
        }
        self.api_executor.edit_share(share_dict)

        _metadata = {}
        _metadata['volID'] = vol_no
        _metadata['volName'] = share_name
        _metadata['thin_provision'] = qnap_thin_provision
        _metadata['compression'] = qnap_compression
        _metadata['deduplication'] = qnap_deduplication
        _metadata['ssd_cache'] = qnap_ssd_cache
        self.private_storage.update(share['id'], _metadata)

        LOG.info("Share %(shr_path)s was successfully managed with ID "
                 "%(shr_id)s.",
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})

        export_locations = self._get_location_path(
            share_name,
            share['share_proto'],
            self.configuration.qnap_share_ip,
            vol_no)

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
