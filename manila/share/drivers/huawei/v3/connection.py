# Copyright (c) 2015 Huawei Technologies Co., Ltd.
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

import time

from oslo_log import log
from oslo_utils import strutils
from oslo_utils import units

from manila.common import constants as common_constants
from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.i18n import _LW
from manila.share.drivers.huawei import base as driver
from manila.share.drivers.huawei import constants
from manila.share.drivers.huawei import huawei_utils
from manila.share.drivers.huawei.v3 import helper
from manila.share.drivers.huawei.v3 import smartx
from manila.share import share_types
from manila.share import utils as share_utils


LOG = log.getLogger(__name__)


class V3StorageConnection(driver.HuaweiBase):
    """Helper class for Huawei OceanStor V3 storage system."""

    def __init__(self, configuration):
        super(V3StorageConnection, self).__init__(configuration)

    def connect(self):
        """Try to connect to V3 server."""
        if self.configuration:
            self.helper = helper.RestHelper(self.configuration)
        else:
            raise exception.InvalidInput(_("Huawei configuration missing."))
        self.helper.login()

    def create_share(self, share, share_server=None):
        """Create a share."""
        share_name = share['name']
        share_proto = share['share_proto']

        pool_name = share_utils.extract_host(share['host'], level='pool')

        if not pool_name:
            msg = _("Pool is not available in the share host field.")
            raise exception.InvalidHost(reason=msg)

        result = self.helper._find_all_pool_info()
        poolinfo = self.helper._find_pool_info(pool_name, result)
        if not poolinfo:
            msg = (_("Can not find pool info by pool name: %s") % pool_name)
            raise exception.InvalidHost(reason=msg)

        fs_id = None
        # We sleep here to ensure the newly created filesystem can be read.
        wait_interval = self._get_wait_interval()
        timeout = self._get_timeout()

        try:
            fs_id = self.allocate_container(share, poolinfo)
            fs = self.helper._get_fs_info_by_id(fs_id)
            end_time = time.time() + timeout

            while not (self.check_fs_status(fs['HEALTHSTATUS'],
                                            fs['RUNNINGSTATUS'])
                       or time.time() > end_time):
                time.sleep(wait_interval)
                fs = self.helper._get_fs_info_by_id(fs_id)

            if not self.check_fs_status(fs['HEALTHSTATUS'],
                                        fs['RUNNINGSTATUS']):
                raise exception.InvalidShare(
                    reason=(_('Invalid status of filesystem: %(health)s '
                              '%(running)s.')
                            % {'health': fs['HEALTHSTATUS'],
                               'running': fs['RUNNINGSTATUS']}))
        except Exception as err:
            if fs_id is not None:
                self.helper._delete_fs(fs_id)
            message = (_('Failed to create share %(name)s.'
                         'Reason: %(err)s.')
                       % {'name': share_name,
                          'err': err})
            raise exception.InvalidShare(reason=message)

        try:
            self.helper._create_share(share_name, fs_id, share_proto)
        except Exception as err:
            if fs_id is not None:
                self.helper._delete_fs(fs_id)
            raise exception.InvalidShare(
                reason=(_('Failed to create share %(name)s. Reason: %(err)s.')
                        % {'name': share_name, 'err': err}))

        location = self._get_location_path(share_name, share_proto)
        return location

    def extend_share(self, share, new_size, share_server):
        share_proto = share['share_proto']
        share_name = share['name']

        # The unit is in sectors.
        size = int(new_size) * units.Mi * 2
        share_url_type = self.helper._get_share_url_type(share_proto)

        share = self.helper._get_share_by_name(share_name, share_url_type)
        if not share:
            err_msg = (_("Can not get share ID by share %s.")
                       % share_name)
            LOG.error(err_msg)
            raise exception.InvalidShareAccess(reason=err_msg)

        fsid = share['FSID']
        fs_info = self.helper._get_fs_info_by_id(fsid)

        current_size = int(fs_info['CAPACITY']) / units.Mi / 2
        if current_size > new_size:
            err_msg = (_("New size for extend must be equal or bigger than "
                         "current size on array. (current: %(size)s, "
                         "new: %(new_size)s).")
                       % {'size': current_size, 'new_size': new_size})

            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)
        self.helper._change_share_size(fsid, size)

    def shrink_share(self, share, new_size, share_server):
        """Shrinks size of existing share."""
        share_proto = share['share_proto']
        share_name = share['name']

        # The unit is in sectors.
        size = int(new_size) * units.Mi * 2
        share_url_type = self.helper._get_share_url_type(share_proto)

        share = self.helper._get_share_by_name(share_name, share_url_type)
        if not share:
            err_msg = (_("Can not get share ID by share %s.")
                       % share_name)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        fsid = share['FSID']
        fs_info = self.helper._get_fs_info_by_id(fsid)
        if not fs_info:
            err_msg = (_("Can not get filesystem info by filesystem ID: %s.")
                       % fsid)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        current_size = int(fs_info['CAPACITY']) / units.Mi / 2
        if current_size < new_size:
            err_msg = (_("New size for shrink must be less than current "
                         "size on array. (current: %(size)s, "
                         "new: %(new_size)s).")
                       % {'size': current_size, 'new_size': new_size})
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        if fs_info['ALLOCTYPE'] != constants.ALLOC_TYPE_THIN_FLAG:
            err_msg = (_("Share (%s) can not be shrunk. only 'Thin' shares "
                         "support shrink.")
                       % share_name)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        self.helper._change_share_size(fsid, size)

    def check_fs_status(self, health_status, running_status):
        if (health_status == constants.STATUS_FS_HEALTH
                and running_status == constants.STATUS_FS_RUNNING):
            return True
        else:
            return False

    def create_snapshot(self, snapshot, share_server=None):
        """Create a snapshot."""
        snap_name = snapshot['id']
        share_proto = snapshot['share']['share_proto']

        share_url_type = self.helper._get_share_url_type(share_proto)
        share = self.helper._get_share_by_name(snapshot['share_name'],
                                               share_url_type)

        if not share:
            err_msg = _('Can not create snapshot,'
                        ' because share id is not provided.')
            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)

        sharefsid = share['FSID']
        snapshot_name = "share_snapshot_" + snap_name
        snap_id = self.helper._create_snapshot(sharefsid,
                                               snapshot_name)
        LOG.info(_LI('Creating snapshot id %s.'), snap_id)

    def delete_snapshot(self, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug("Delete a snapshot.")
        snap_name = snapshot['id']

        sharefsid = self.helper._get_fsid_by_name(snapshot['share_name'])

        if sharefsid is None:
            LOG.warning(_LW('Delete snapshot share id %s fs has been '
                        'deleted.'), snap_name)
            return

        snapshot_id = self.helper._get_snapshot_id(sharefsid, snap_name)
        snapshot_flag = self.helper._check_snapshot_id_exist(snapshot_id)

        if snapshot_flag:
            self.helper._delete_snapshot(snapshot_id)
        else:
            LOG.warning(_LW("Can not find snapshot %s on array."), snap_name)

    def update_share_stats(self, stats_dict):
        """Retrieve status info from share group."""
        root = self.helper._read_xml()
        all_pool_info = self.helper._find_all_pool_info()
        stats_dict["pools"] = []

        pool_name_list = root.findtext('Filesystem/StoragePool')
        pool_name_list = pool_name_list.split(";")
        for pool_name in pool_name_list:
            pool_name = pool_name.strip().strip('\n')
            capacity = self._get_capacity(pool_name, all_pool_info)
            if capacity:
                pool = dict(
                    pool_name=pool_name,
                    total_capacity_gb=capacity['TOTALCAPACITY'],
                    free_capacity_gb=capacity['CAPACITY'],
                    provisioned_capacity_gb=(
                        capacity['PROVISIONEDCAPACITYGB']),
                    max_over_subscription_ratio=(
                        self.configuration.safe_get(
                            'max_over_subscription_ratio')),
                    allocated_capacity_gb=capacity['CONSUMEDCAPACITY'],
                    qos=False,
                    reserved_percentage=0,
                    thin_provisioning=[True, False],
                    dedupe=[True, False],
                    compression=[True, False],
                    huawei_smartcache=[True, False],
                    huawei_smartpartition=[True, False],
                )
                stats_dict["pools"].append(pool)

        if not stats_dict["pools"]:
            err_msg = _("The StoragePool is None.")
            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)

    def delete_share(self, share, share_server=None):
        """Delete share."""
        share_name = share['name']
        share_url_type = self.helper._get_share_url_type(share['share_proto'])
        share = self.helper._get_share_by_name(share_name, share_url_type)

        if not share:
            LOG.warning(_LW('The share was not found. Share name:%s'),
                        share_name)
            fsid = self.helper._get_fsid_by_name(share_name)
            if fsid:
                self.helper._delete_fs(fsid)
                return
            LOG.warning(_LW('The filesystem was not found.'))
            return

        share_id = share['ID']
        share_fs_id = share['FSID']

        if share_id:
            self.helper._delete_share_by_id(share_id, share_url_type)

        if share_fs_id:
            self.helper._delete_fs(share_fs_id)

        return share

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return constants.IP_ALLOCATIONS

    def _get_capacity(self, pool_name, result):
        """Get free capacity and total capacity of the pools."""
        poolinfo = self.helper._find_pool_info(pool_name, result)

        if poolinfo:
            total = float(poolinfo['TOTALCAPACITY']) / units.Mi / 2
            free = float(poolinfo['CAPACITY']) / units.Mi / 2
            consumed = float(poolinfo['CONSUMEDCAPACITY']) / units.Mi / 2
            poolinfo['TOTALCAPACITY'] = total
            poolinfo['CAPACITY'] = free
            poolinfo['CONSUMEDCAPACITY'] = consumed
            poolinfo['PROVISIONEDCAPACITYGB'] = round(
                float(total) - float(free), 2)

        return poolinfo

    def _init_filesys_para(self, share, poolinfo, extra_specs):
        """Init basic filesystem parameters."""
        name = share['name']
        size = int(share['size']) * units.Mi * 2
        fileparam = {
            "NAME": name.replace("-", "_"),
            "DESCRIPTION": "",
            "ALLOCTYPE": constants.ALLOC_TYPE_THIN_FLAG,
            "CAPACITY": size,
            "PARENTID": poolinfo['ID'],
            "INITIALALLOCCAPACITY": units.Ki * 20,
            "PARENTTYPE": 216,
            "SNAPSHOTRESERVEPER": 20,
            "INITIALDISTRIBUTEPOLICY": 0,
            "ISSHOWSNAPDIR": True,
            "RECYCLESWITCH": 0,
            "RECYCLEHOLDTIME": 15,
            "RECYCLETHRESHOLD": 0,
            "RECYCLEAUTOCLEANSWITCH": 0,
            "ENABLEDEDUP": extra_specs['dedupe'],
            "ENABLECOMPRESSION": extra_specs['compression'],
        }

        if 'LUNType' in extra_specs:
            fileparam['ALLOCTYPE'] = extra_specs['LUNType']
        else:
            root = self.helper._read_xml()
            fstype = root.findtext('Filesystem/AllocType')
            if fstype:
                fstype = fstype.strip().strip('\n')
                if fstype == 'Thin':
                    fileparam['ALLOCTYPE'] = constants.ALLOC_TYPE_THIN_FLAG
                elif fstype == 'Thick':
                    fileparam['ALLOCTYPE'] = constants.ALLOC_TYPE_THICK_FLAG
                else:
                    err_msg = (_(
                        'Config file is wrong. AllocType type must be set to'
                        ' "Thin" or "Thick". AllocType:%(fetchtype)s') %
                        {'fetchtype': fstype})
                    LOG.error(err_msg)
                    raise exception.InvalidShare(reason=err_msg)

        if fileparam['ALLOCTYPE'] == 0:
            if (extra_specs['dedupe'] or
                    extra_specs['compression']):
                err_msg = _(
                    'The filesystem type is "Thick",'
                    ' so dedupe or compression cannot be set.')
                LOG.error(err_msg)
                raise exception.InvalidInput(reason=err_msg)

        return fileparam

    def deny_access(self, share, access, share_server=None):
        """Deny access to share."""
        share_proto = share['share_proto']
        share_name = share['name']
        share_url_type = self.helper._get_share_url_type(share_proto)
        share_client_type = self.helper._get_share_client_type(share_proto)
        access_type = access['access_type']
        if share_proto == 'NFS' and access_type != 'ip':
            LOG.warning(_LW('Only IP access type is allowed for NFS shares.'))
            return
        elif share_proto == 'CIFS' and access_type != 'user':
            LOG.warning(_LW('Only USER access type is allowed for'
                            ' CIFS shares.'))
            return

        access_to = access['access_to']
        share = self.helper._get_share_by_name(share_name, share_url_type)
        if not share:
            LOG.warning(_LW('Can not get share. share_name: %s'), share_name)
            return

        access_id = self.helper._get_access_from_share(share['ID'], access_to,
                                                       share_client_type)
        if not access_id:
            LOG.warning(_LW('Can not get access id from share. '
                            'share_name: %s'), share_name)
            return

        self.helper._remove_access_from_share(access_id, share_client_type)

    def allow_access(self, share, access, share_server=None):
        """Allow access to the share."""
        share_proto = share['share_proto']
        share_name = share['name']
        share_url_type = self.helper._get_share_url_type(share_proto)
        access_type = access['access_type']
        access_level = access['access_level']

        if access_level not in common_constants.ACCESS_LEVELS:
            raise exception.InvalidShareAccess(
                reason=(_('Unsupported level of access was provided - %s') %
                        access_level))

        if share_proto == 'NFS':
            if access_type == 'ip':
                if access_level == common_constants.ACCESS_LEVEL_RW:
                    access_level = constants.ACCESS_NFS_RW
                else:
                    access_level = constants.ACCESS_NFS_RO
            else:
                message = _('Only IP access type is allowed for NFS shares.')
                raise exception.InvalidShareAccess(reason=message)
        elif share_proto == 'CIFS':
            if access_type == 'user':
                if access_level == common_constants.ACCESS_LEVEL_RW:
                    access_level = constants.ACCESS_CIFS_RW
                else:
                    access_level = constants.ACCESS_CIFS_RO
            else:
                message = _('Only USER access type is allowed'
                            ' for CIFS shares.')
                raise exception.InvalidShareAccess(reason=message)

        share = self.helper._get_share_by_name(share_name, share_url_type)
        if not share:
            err_msg = (_("Can not get share ID by share %s.")
                       % share_name)
            LOG.error(err_msg)
            raise exception.InvalidShareAccess(reason=err_msg)

        share_id = share['ID']
        access_to = access['access_to']
        self.helper._allow_access_rest(share_id, access_to,
                                       share_proto, access_level)

    def get_pool(self, share):
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if pool_name:
            return pool_name
        share_name = share['name']
        share_url_type = self.helper._get_share_url_type(share['share_proto'])
        share = self.helper._get_share_by_name(share_name, share_url_type)

        pool_name = None
        if share:
            pool = self.helper._get_fs_info_by_id(share['FSID'])
            pool_name = pool['POOLNAME']

        return pool_name

    def allocate_container(self, share, poolinfo):
        """Creates filesystem associated to share by name."""
        opts = huawei_utils.get_share_extra_specs_params(
            share['share_type_id'])

        smartx_opts = constants.OPTS_CAPABILITIES
        if opts is not None:
            smart = smartx.SmartX()
            smartx_opts = smart.get_smartx_extra_specs_opts(opts)

        fileParam = self._init_filesys_para(share, poolinfo, smartx_opts)
        fsid = self.helper._create_filesystem(fileParam)

        try:
            smartpartition = smartx.SmartPartition(self.helper)
            smartpartition.add(opts, fsid)

            smartcache = smartx.SmartCache(self.helper)
            smartcache.add(opts, fsid)
        except Exception as err:
            if fsid is not None:
                self.helper._delete_fs(fsid)
            message = (_('Failed to add smartx. Reason: %(err)s.')
                       % {'err': err})
            raise exception.InvalidShare(reason=message)
        return fsid

    def manage_existing(self, share, driver_options):
        """Manage existing share."""

        share_proto = share['share_proto']
        share_name = share['name']
        old_export_location = share['export_locations'][0]['path']
        pool_name = share_utils.extract_host(share['host'], level='pool')
        share_url_type = self.helper._get_share_url_type(share_proto)
        old_share_name = self.helper._get_share_name_by_export_location(
            old_export_location, share_proto)

        share_storage = self.helper._get_share_by_name(old_share_name,
                                                       share_url_type)
        if not share_storage:
            err_msg = (_("Can not get share ID by share %s.")
                       % old_export_location)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        fs_id = share_storage['FSID']
        fs = self.helper._get_fs_info_by_id(fs_id)
        if not self.check_fs_status(fs['HEALTHSTATUS'],
                                    fs['RUNNINGSTATUS']):
            raise exception.InvalidShare(
                reason=(_('Invalid status of filesystem: %(health)s '
                          '%(running)s.')
                        % {'health': fs['HEALTHSTATUS'],
                           'running': fs['RUNNINGSTATUS']}))

        if pool_name and pool_name != fs['POOLNAME']:
            raise exception.InvalidHost(
                reason=(_('The current pool(%(fs_pool)s) of filesystem '
                          'does not match the input pool(%(host_pool)s).')
                        % {'fs_pool': fs['POOLNAME'],
                           'host_pool': pool_name}))

        result = self.helper._find_all_pool_info()
        poolinfo = self.helper._find_pool_info(pool_name, result)

        opts = huawei_utils.get_share_extra_specs_params(
            share['share_type_id'])
        specs = share_types.get_share_type_extra_specs(share['share_type_id'])
        if ('capabilities:thin_provisioning' not in specs.keys()
                and 'thin_provisioning' not in specs.keys()):
            if fs['ALLOCTYPE'] == constants.ALLOC_TYPE_THIN_FLAG:
                opts['thin_provisioning'] = constants.THIN_PROVISIONING
            else:
                opts['thin_provisioning'] = constants.THICK_PROVISIONING

        change_opts = self.check_retype_change_opts(opts, poolinfo, fs)
        LOG.info(_LI('Retyping share (%(share)s), changed options are : '
                     '(%(change_opts)s).'),
                 {'share': old_share_name, 'change_opts': change_opts})
        try:
            self.retype_share(change_opts, fs_id)
        except Exception as err:
            message = (_("Retype share error. Share: %(share)s. "
                         "Reason: %(reason)s.")
                       % {'share': old_share_name,
                          'reason': err})
            raise exception.InvalidShare(reason=message)

        share_size = int(fs['CAPACITY']) / units.Mi / 2
        self.helper._change_fs_name(fs_id, share_name)
        location = self._get_location_path(share_name, share_proto)
        return (share_size, [location])

    def check_retype_change_opts(self, opts, poolinfo, fs):
        change_opts = {
            "partitionid": None,
            "cacheid": None,
            "dedupe&compression": None,
        }

        # SmartPartition
        old_partition_id = fs['SMARTPARTITIONID']
        old_partition_name = None
        new_partition_id = None
        new_partition_name = None
        if strutils.bool_from_string(opts['huawei_smartpartition']):
            if not opts['partitionname']:
                raise exception.InvalidInput(
                    reason=_('Partition name is None, please set '
                             'huawei_smartpartition:partitionname in key.'))
            new_partition_name = opts['partitionname']
            new_partition_id = self.helper._get_partition_id_by_name(
                new_partition_name)
            if new_partition_id is None:
                raise exception.InvalidInput(
                    reason=(_("Can't find partition name on the array, "
                              "partition name is: %(name)s.")
                            % {"name": new_partition_name}))

        if old_partition_id != new_partition_id:
            if old_partition_id:
                partition_info = self.helper.get_partition_info_by_id(
                    old_partition_id)
                old_partition_name = partition_info['NAME']
            change_opts["partitionid"] = ([old_partition_id,
                                           old_partition_name],
                                          [new_partition_id,
                                           new_partition_name])

        # SmartCache
        old_cache_id = fs['SMARTCACHEID']
        old_cache_name = None
        new_cache_id = None
        new_cache_name = None
        if strutils.bool_from_string(opts['huawei_smartcache']):
            if not opts['cachename']:
                raise exception.InvalidInput(
                    reason=_('Cache name is None, please set '
                             'huawei_smartcache:cachename in key.'))
            new_cache_name = opts['cachename']
            new_cache_id = self.helper._get_cache_id_by_name(
                new_cache_name)
            if new_cache_id is None:
                raise exception.InvalidInput(
                    reason=(_("Can't find cache name on the array, "
                              "cache name is: %(name)s.")
                            % {"name": new_cache_name}))

        if old_cache_id != new_cache_id:
            if old_cache_id:
                cache_info = self.helper.get_cache_info_by_id(
                    old_cache_id)
                old_cache_name = cache_info['NAME']
            change_opts["cacheid"] = ([old_cache_id, old_cache_name],
                                      [new_cache_id, new_cache_name])

        # SmartDedupe&SmartCompression
        smartx_opts = constants.OPTS_CAPABILITIES
        if opts is not None:
            smart = smartx.SmartX()
            smartx_opts = smart.get_smartx_extra_specs_opts(opts)

        old_compression = fs['COMPRESSION']
        new_compression = smartx_opts['compression']
        old_dedupe = fs['DEDUP']
        new_dedupe = smartx_opts['dedupe']

        if fs['ALLOCTYPE'] == constants.ALLOC_TYPE_THIN_FLAG:
            fs['ALLOCTYPE'] = constants.ALLOC_TYPE_THIN
        else:
            fs['ALLOCTYPE'] = constants.ALLOC_TYPE_THICK

        if strutils.bool_from_string(opts['thin_provisioning']):
            opts['thin_provisioning'] = constants.ALLOC_TYPE_THIN
        else:
            opts['thin_provisioning'] = constants.ALLOC_TYPE_THICK

        if fs['ALLOCTYPE'] != opts['thin_provisioning']:
            msg = (_("Manage existing share "
                     "fs type and new_share_type mismatch. "
                     "fs type is: %(fs_type)s, "
                     "new_share_type is: %(new_share_type)s")
                   % {"fs_type": fs['ALLOCTYPE'],
                      "new_share_type": opts['thin_provisioning']})
            raise exception.InvalidHost(reason=msg)
        else:
            if fs['ALLOCTYPE'] == constants.ALLOC_TYPE_THICK:
                if new_compression or new_dedupe:
                    raise exception.InvalidInput(
                        reason=_("Dedupe or compression cannot be set for "
                                 "thick filesystem."))
            else:
                if (old_dedupe != new_dedupe
                        or old_compression != new_compression):
                    change_opts["dedupe&compression"] = ([old_dedupe,
                                                          old_compression],
                                                         [new_dedupe,
                                                          new_compression])
        return change_opts

    def retype_share(self, change_opts, fs_id):
        if change_opts.get('partitionid'):
            old, new = change_opts['partitionid']
            old_id = old[0]
            old_name = old[1]
            new_id = new[0]
            new_name = new[1]

            if old_id:
                self.helper._remove_fs_from_partition(fs_id, old_id)
            if new_id:
                self.helper._add_fs_to_partition(fs_id, new_id)
                msg = (_("Retype FS(id: %(fs_id)s) smartpartition from "
                         "(name: %(old_name)s, id: %(old_id)s) to "
                         "(name: %(new_name)s, id: %(new_id)s) "
                         "performed successfully.")
                       % {"fs_id": fs_id,
                          "old_id": old_id, "old_name": old_name,
                          "new_id": new_id, "new_name": new_name})
                LOG.info(msg)

        if change_opts.get('cacheid'):
            old, new = change_opts['cacheid']
            old_id = old[0]
            old_name = old[1]
            new_id = new[0]
            new_name = new[1]
            if old_id:
                self.helper._remove_fs_from_cache(fs_id, old_id)
            if new_id:
                self.helper._add_fs_to_cache(fs_id, new_id)
                msg = (_("Retype FS(id: %(fs_id)s) smartcache from "
                         "(name: %(old_name)s, id: %(old_id)s) to "
                         "(name: %(new_name)s, id: %(new_id)s) "
                         "performed successfully.")
                       % {"fs_id": fs_id,
                          "old_id": old_id, "old_name": old_name,
                          "new_id": new_id, "new_name": new_name})
                LOG.info(msg)

        if change_opts.get('dedupe&compression'):
            old, new = change_opts['dedupe&compression']
            old_dedupe = old[0]
            old_compression = old[1]
            new_dedupe = new[0]
            new_compression = new[1]
            if ((old_dedupe != new_dedupe)
                    or (old_compression != new_compression)):

                new_smartx_opts = {"dedupe": new_dedupe,
                                   "compression": new_compression}

                self.helper._change_extra_specs(fs_id, new_smartx_opts)
                msg = (_("Retype FS(id: %(fs_id)s) dedupe from %(old_dedupe)s "
                         "to %(new_dedupe)s performed successfully, "
                         "compression from "
                         "%(old_compression)s to %(new_compression)s "
                         "performed successfully.")
                       % {"fs_id": fs_id,
                          "old_dedupe": old_dedupe,
                          "new_dedupe": new_dedupe,
                          "old_compression": old_compression,
                          "new_compression": new_compression})
                LOG.info(msg)

    def _get_location_path(self, share_name, share_proto):
        root = self.helper._read_xml()
        target_ip = root.findtext('Storage/LogicalPortIP').strip()

        location = None
        if share_proto == 'NFS':
            location = '%s:/%s' % (target_ip,
                                   share_name.replace("-", "_"))
        elif share_proto == 'CIFS':
            location = '\\\\%s\\%s' % (target_ip,
                                       share_name.replace("-", "_"))
        else:
            raise exception.InvalidShareAccess(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        return location

    def _get_wait_interval(self):
        """Get wait interval from huawei conf file."""
        root = self.helper._read_xml()
        wait_interval = root.findtext('Filesystem/WaitInterval')
        if wait_interval:
            return int(wait_interval)
        else:
            LOG.info(_LI(
                "Wait interval is not configured in huawei "
                "conf file. Use default: %(default_wait_interval)d."),
                {"default_wait_interval": constants.DEFAULT_WAIT_INTERVAL})
            return constants.DEFAULT_WAIT_INTERVAL

    def _get_timeout(self):
        """Get timeout from huawei conf file."""
        root = self.helper._read_xml()
        timeout = root.findtext('Filesystem/Timeout')
        if timeout:
            return int(timeout)
        else:
            LOG.info(_LI(
                "Timeout is not configured in huawei conf file. "
                "Use default: %(default_timeout)d."),
                {"default_timeout": constants.DEFAULT_TIMEOUT})
            return constants.DEFAULT_TIMEOUT

    def check_conf_file(self):
        """Check the config file, make sure the essential items are set."""
        root = self.helper._read_xml()
        resturl = root.findtext('Storage/RestURL')
        username = root.findtext('Storage/UserName')
        pwd = root.findtext('Storage/UserPassword')
        product = root.findtext('Storage/Product')
        pool_node = root.findtext('Filesystem/StoragePool')

        if product != "V3":
            err_msg = (_(
                'check_conf_file: Config file invalid. '
                'Product must be set to V3.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if not (resturl and username and pwd):
            err_msg = (_(
                'check_conf_file: Config file invalid. RestURL,'
                ' UserName and UserPassword must be set.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if not pool_node:
            err_msg = (_(
                'check_conf_file: Config file invalid. '
                'StoragePool must be set.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

    def check_service(self):
        running_status = self.helper._get_cifs_service_status()
        if running_status != constants.STATUS_SERVICE_RUNNING:
            self.helper._start_cifs_service_status()

        service = self.helper._get_nfs_service_status()
        if ((service['RUNNINGSTATUS'] != constants.STATUS_SERVICE_RUNNING) or
                (service['SUPPORTV3'] == 'false') or
                (service['SUPPORTV4'] == 'false')):
            self.helper._start_nfs_service_status()
