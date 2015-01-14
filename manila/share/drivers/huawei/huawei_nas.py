# Copyright (c) 2014 Huawei Technologies Co., Ltd.
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

"""Huawei Nas Driver for Huawei OceanStor V3 storage arrays."""
import time

from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import units

from manila import exception
from manila.i18n import _, _LI, _LW
from manila.openstack.common import log as logging
from manila.openstack.common import loopingcall
from manila.share import driver
from manila.share.drivers.huawei import constants
from manila.share.drivers.huawei import huawei_helper

huawei_opts = [
    cfg.StrOpt('manila_huawei_conf_file',
               default='/etc/manila/manila_huawei_conf.xml',
               help='The configuration file for the Manila Huawei driver.')]

CONF = cfg.CONF
CONF.register_opts(huawei_opts)
LOG = logging.getLogger(__name__)


class HuaweiNasDriver(driver.ShareDriver):
    """Huawei Share Driver.

    Executes commands relating to Shares.
    API version history:

        1.0 - Initial version.
    """

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        LOG.debug("Enter into init function.")
        super(HuaweiNasDriver, self).__init__(False, *args, **kwargs)
        self.configuration = kwargs.get('configuration', None)
        if self.configuration:
            self.configuration.append_config_values(huawei_opts)
            self.helper = huawei_helper.RestHelper(self.configuration)
        else:
            raise exception.InvalidShare(_("Huawei configuration missing."))

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        self.helper._check_conf_file()
        self.helper._check_service()

    def do_setup(self, context):
        """Any initialization the huawei nas driver does while starting."""
        LOG.debug("Do setup the plugin.")
        return self.helper.login()

    def create_share(self, context, share, share_server=None):
        """Create a share."""
        LOG.debug("Create a share.")
        share_name = share['name']
        size = share['size'] * units.Mi * 2

        fs_id = None
        # We sleep here to ensure the newly created filesystem can be read.
        wait_interval = self._get_wait_interval()
        try:
            fs_id = self.helper.allocate_container(share_name, size)

            def _create_share_complete():
                fs = self.helper._get_fs_info_by_id(fs_id)
                if fs['HEALTHSTATUS'] == constants.STATUS_FS_HEALTH\
                   and fs['RUNNINGSTATUS'] == constants.STATUS_FS_RUNNING:
                    return True
                else:
                    return False
            self._wait_for_condition(_create_share_complete,
                                     int(wait_interval))
        except Exception:
            with excutils.save_and_reraise_exception():
                if fs_id is not None:
                    self.helper._delete_fs(fs_id)
                raise exception.InvalidShare('The status of filesystem error.')

        try:
            self.helper._create_share(share_name, fs_id, share['share_proto'])
        except Exception:
            with excutils.save_and_reraise_exception():
                if fs_id is not None:
                    self.helper._delete_fs(fs_id)

        share_path = self.helper._get_share_path(share_name)

        root = self.helper._read_xml()
        target_ip = root.findtext('Storage/LogicalPortIP').strip()
        location = ':'.join([target_ip, share_path])

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        LOG.debug("Create share from snapshot.")
        raise NotImplementedError()

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        LOG.debug("Delete a share.")

        self.helper._delete_share(share['name'], share['share_proto'])

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        snap_name = snapshot['id']
        share_proto = snapshot['share_proto']

        share_name = self.helper._get_share_name_by_id(snapshot['share_id'])
        share_type = self.helper._get_share_type(share_proto)
        share = self.helper._get_share_by_name(share_name, share_type)

        if not share:
            err_msg = (_("Create a snapshot,share fs id is empty."))
            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)

        sharefsid = share['FSID']
        snapshot_name = "share_snapshot_" + snap_name
        snap_id = self.helper._create_snapshot(sharefsid,
                                               snapshot_name)
        LOG.info(_LI('Creating snapshot id %s.'), snap_id)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug("Delete a snapshot.")
        snap_name = snapshot['id']

        share_name = self.helper._get_share_name_by_id(snapshot['share_id'])
        sharefsid = self.helper._get_fsid_by_name(share_name)

        if sharefsid is None:
            LOG.warn(_LW('Delete snapshot share id %s fs has been deleted.'),
                     snap_name)
            return

        snapshot_id = self.helper._get_snapshot_id_by_name(sharefsid,
                                                           snap_name)
        if snapshot_id is not None:
            self.helper._delete_snapshot(snapshot_id)
        else:
            LOG.warn(_LW("Can not find snapshot %s in array."), snap_name)

    def ensure_share(self, context, share, share_server=None):
        """Ensure that storages are mounted and exported."""
        LOG.debug("Ensure share.")

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        LOG.debug("Allow access.")

        self.helper._allow_access(share['name'], access, share['share_proto'])

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        LOG.debug("Deny access.")

        self.helper._deny_access(share['name'], access, share['share_proto'])

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        LOG.debug("Get network allocations number.")
        return constants.IP_ALLOCATIONS

    def _update_share_stats(self):
        """Retrieve status info from share group."""

        backend_name = self.configuration.safe_get('share_backend_name')
        capacity = self.helper._get_capacity()
        data = dict(
            share_backend_name=backend_name or 'HUAWEI_NAS_Driver',
            vendor_name='Huawei',
            storage_protocol='NFS_CIFS',
            total_capacity_gb=capacity['total_capacity'],
            free_capacity_gb=capacity['free_capacity'])
        super(HuaweiNasDriver, self)._update_share_stats(data)

    def _get_wait_interval(self):
        """Get wait interval from huawei conf file."""
        root = self.helper._read_xml()
        wait_interval = root.findtext('Filesystem/WaitInterval')
        if wait_interval:
            return wait_interval
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
            return timeout
        else:
            LOG.info(_LI(
                "Timeout is not configured in huawei conf file. "
                "Use default: %(default_timeout)d."),
                {"default_timeout": constants.DEFAULT_TIMEOUT})
            return constants.DEFAULT_TIMEOUT

    def _wait_for_condition(self, func, interval, timeout=None):
        start_time = time.time()
        if timeout is None:
            timeout = self._get_timeout()

        def _inner():
            try:
                res = func()
            except Exception as ex:
                res = False
                LOG.debug('_wait_for_condition: %(func_name)s '
                          'failed for %(exception)s.',
                          {'func_name': func.__name__,
                           'exception': ex.message})
            if res:
                raise loopingcall.LoopingCallDone()

            if int(time.time()) - int(start_time) > int(timeout):
                msg = (_('_wait_for_condition: %s timed out.'),
                       func.__name__)
                LOG.error(msg)
                raise exception.InvalidShare(data=msg)

        timer = loopingcall.FixedIntervalLoopingCall(_inner)
        timer.start(interval=interval).wait()
