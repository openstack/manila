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
from oslo_utils import units

from manila.common import constants as common_constants
from manila import exception
from manila.i18n import _, _LI, _LW
from manila.share.drivers.huawei import base as driver
from manila.share.drivers.huawei import constants
from manila.share.drivers.huawei.v3 import helper

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

        fs_id = None
        # We sleep here to ensure the newly created filesystem can be read.
        wait_interval = self._get_wait_interval()
        timeout = self._get_timeout()

        try:
            fs_id = self.allocate_container(share)
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
                reason=(_('Failed to create share %(name)s.'
                          'Reason: %(err)s.')
                        % {'name': share_name,
                           'err': err}))

        location = self._get_location_path(share_name, share_proto)
        return location

    def extend_share(self, share, new_size, share_server):
        share_proto = share['share_proto']
        share_name = share['name']

        # The unit is the sectors.
        size = new_size * units.Mi * 2
        share_type = self.helper._get_share_type(share_proto)

        share = self.helper._get_share_by_name(share_name, share_type)
        if not share:
            err_msg = (_("Can not get share ID by share %s.")
                       % share_name)
            LOG.error(err_msg)
            raise exception.InvalidShareAccess(reason=err_msg)

        fsid = share['FSID']
        self.helper._extend_share(fsid, size)

    def check_fs_status(self, health_status, running_status):
        if (health_status == constants.STATUS_FS_HEALTH
                and running_status == constants.STATUS_FS_RUNNING):
            return True
        else:
            return False

    def create_snapshot(self, snapshot, share_server=None):
        """Create a snapshot."""
        snap_name = snapshot['id']
        share_proto = snapshot['share_proto']

        share_name = self.helper._get_share_name_by_id(snapshot['share_id'])
        share_type = self.helper._get_share_type(share_proto)
        share = self.helper._get_share_by_name(share_name, share_type)

        if not share:
            err_msg = _('Can not create snapshot,'
                        ' because share_id is not provided.')
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

        share_name = self.helper._get_share_name_by_id(snapshot['share_id'])
        sharefsid = self.helper._get_fsid_by_name(share_name)

        if sharefsid is None:
            LOG.warning(_LW('Delete snapshot share id %s fs has been '
                        'deleted.'), snap_name)
            return

        snapshot_id = self.helper._get_snapshot_id(sharefsid, snap_name)
        snapshot_flag = self.helper._check_snapshot_id_exist(snapshot_id)

        if snapshot_flag:
            self.helper._delete_snapshot(snapshot_id)
        else:
            LOG.warning(_LW("Can not find snapshot %s in array."), snap_name)

    def update_share_stats(self, stats_dict):
        """Retrieve status info from share group."""
        capacity = self._get_capacity()

        stats_dict["pools"] = []
        pool = {}
        pool.update(dict(
            pool_name=capacity['name'],
            total_capacity_gb=capacity['TOTALCAPACITY'],
            free_capacity_gb=capacity['CAPACITY'],
            QoS_support=False,
            reserved_percentage=0,
        ))
        stats_dict["pools"].append(pool)

    def delete_share(self, share, share_server=None):
        """Delete share."""
        share_name = share['name']
        share_proto = self.helper._get_share_type(share['share_proto'])
        share = self.helper._get_share_by_name(share_name, share_proto)

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
            self.helper._delete_share_by_id(share_id, share_proto)

        if share_fs_id:
            self.helper._delete_fs(share_fs_id)

        return share

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return constants.IP_ALLOCATIONS

    def _get_capacity(self):
        """Get free capacity and total capacity of the pools."""
        poolinfo = self.helper._find_pool_info()

        if poolinfo:
            total = int(poolinfo['TOTALCAPACITY']) / units.Mi / 2
            free = int(poolinfo['CAPACITY']) / units.Mi / 2
            poolinfo['TOTALCAPACITY'] = total
            poolinfo['CAPACITY'] = free

        return poolinfo

    def _init_filesys_para(self, share):
        """Init basic filesystem parameters."""
        name = share['name']
        size = share['size'] * units.Mi * 2
        poolinfo = self.helper._find_pool_info()
        fileparam = {
            "NAME": name.replace("-", "_"),
            "DESCRIPTION": "",
            "ALLOCTYPE": 1,
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
            "ENABLEDEDUP": False,
            "ENABLECOMPRESSION": False,
        }

        root = self.helper._read_xml()
        fstype = root.findtext('Filesystem/AllocType')
        if fstype:
            fstype = fstype.strip()
            if fstype == 'Thin':
                fileparam['ALLOCTYPE'] = 1
            elif fstype == 'Thick':
                fileparam['ALLOCTYPE'] = 0
            else:
                err_msg = (_(
                    'Config file is wrong. Filesystem type must be "Thin"'
                    ' or "Thick". AllocType:%(fetchtype)s') %
                    {'fetchtype': fstype})
                LOG.error(err_msg)
                raise exception.InvalidShare(reason=err_msg)

        return fileparam

    def deny_access(self, share, access, share_server=None):
        """Deny access to share."""
        share_proto = share['share_proto']
        share_name = share['name']
        share_type = self.helper._get_share_type(share_proto)
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
        share = self.helper._get_share_by_name(share_name, share_type)
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
        share_type = self.helper._get_share_type(share_proto)
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

        share = self.helper._get_share_by_name(share_name, share_type)
        if not share:
            err_msg = (_("Can not get share ID by share %s.")
                       % share_name)
            LOG.error(err_msg)
            raise exception.InvalidShareAccess(reason=err_msg)

        share_id = share['ID']
        access_to = access['access_to']
        self.helper._allow_access_rest(share_id, access_to,
                                       share_proto, access_level)

    def allocate_container(self, share):
        """Creates filesystem associated to share by name."""
        fileParam = self._init_filesys_para(share)
        fsid = self.helper._create_filesystem(fileParam)
        return fsid

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
                '_check_conf_file: Config file invalid. '
                'Product must be set to V3.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if not (resturl and username and pwd):
            err_msg = (_(
                '_check_conf_file: Config file invalid. RestURL,'
                ' UserName and UserPassword must be set.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if not pool_node:
            err_msg = (_(
                '_check_conf_file: Config file invalid. '
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
