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

"""Huawei Nas Driver for Huawei storage arrays."""
from xml.etree import ElementTree as ET

from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils

from manila import exception
from manila.i18n import _
from manila.share import driver


HUAWEI_UNIFIED_DRIVER_REGISTRY = {
    'V3': 'manila.share.drivers.huawei.v3.connection.V3StorageConnection', }


huawei_opts = [
    cfg.StrOpt('manila_huawei_conf_file',
               default='/etc/manila/manila_huawei_conf.xml',
               help='The configuration file for the Manila Huawei driver.')]

CONF = cfg.CONF
CONF.register_opts(huawei_opts)
LOG = log.getLogger(__name__)


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
            backend_driver = self.get_backend_driver()
            self.plugin = importutils.import_object(backend_driver,
                                                    self.configuration)
        else:
            raise exception.InvalidShare(_("Huawei configuration missing."))

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        self.plugin.check_conf_file()
        self.plugin.check_service()

    def get_backend_driver(self):
        filename = self.configuration.manila_huawei_conf_file

        try:
            tree = ET.parse(filename)
            root = tree.getroot()
        except Exception as err:
            message = (_('Read Huawei config file(%(filename)s)'
                         ' for Manila error: %(err)s')
                       % {'filename': filename,
                          'err': err})
            LOG.error(message)
            raise exception.InvalidInput(reason=message)
        product = root.findtext('Storage/Product')
        backend_driver = HUAWEI_UNIFIED_DRIVER_REGISTRY.get(product)
        if backend_driver is None:
            raise exception.InvalidInput(
                reason=_('Storage %s is not supported.') % product)

        return backend_driver

    def do_setup(self, context):
        """Any initialization the huawei nas driver does while starting."""
        LOG.debug("Do setup the plugin.")
        self.plugin.connect()

    def create_share(self, context, share, share_server=None):
        """Create a share."""
        LOG.debug("Create a share.")
        location = self.plugin.create_share(share, share_server)
        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        LOG.debug("Create share from snapshot.")
        raise NotImplementedError()

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        LOG.debug("Delete a share.")

        self.plugin.delete_share(share, share_server)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot."""
        self.plugin.create_snapshot(snapshot, share_server)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        LOG.debug("Delete a snapshot.")
        self.plugin.delete_snapshot(snapshot, share_server)

    def ensure_share(self, context, share, share_server=None):
        """Ensure that storages are mounted and exported."""
        LOG.debug("Ensure share.")

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        LOG.debug("Allow access.")

        self.plugin.allow_access(share, access, share_server)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        LOG.debug("Deny access.")

        self.plugin.deny_access(share, access, share_server)

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        LOG.debug("Get network allocations number.")
        return self.plugin.get_network_allocations_number()

    def _update_share_stats(self):
        """Retrieve status info from share group."""

        backend_name = self.configuration.safe_get('share_backend_name')
        data = dict(
            share_backend_name=backend_name or 'HUAWEI_NAS_Driver',
            vendor_name='Huawei',
            storage_protocol='NFS_CIFS')

        self.plugin.update_share_stats(data)
        super(HuaweiNasDriver, self)._update_share_stats(data)
