# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
Unified driver for NetApp storage systems.

Supports multiple storage systems of different families and driver modes.
"""

from oslo_log import log
from oslo_utils import importutils

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.netapp import options
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)

MULTI_SVM = 'multi_svm'
SINGLE_SVM = 'single_svm'
DATAONTAP_CMODE_PATH = 'manila.share.drivers.netapp.dataontap.cluster_mode'

# Add new drivers here, no other code changes required.
NETAPP_UNIFIED_DRIVER_REGISTRY = {
    'ontap_cluster':
    {
        MULTI_SVM: DATAONTAP_CMODE_PATH +
        '.drv_multi_svm.NetAppCmodeMultiSvmShareDriver',
        SINGLE_SVM: DATAONTAP_CMODE_PATH +
        '.drv_single_svm.NetAppCmodeSingleSvmShareDriver',
    },
}
NETAPP_UNIFIED_DRIVER_DEFAULT_MODE = {
    'ontap_cluster': MULTI_SVM,
}


class NetAppDriver(object):
    """"NetApp unified share storage driver.

    Acts as a factory to create NetApp storage drivers based on the
    storage family and driver mode configured.
    """

    REQUIRED_FLAGS = ['netapp_storage_family', 'driver_handles_share_servers']

    def __new__(cls, *args, **kwargs):

        config = kwargs.get('configuration', None)
        if not config:
            raise exception.InvalidInput(
                reason=_('Required configuration not found.'))

        config.append_config_values(driver.share_opts)
        config.append_config_values(options.netapp_proxy_opts)
        na_utils.check_flags(NetAppDriver.REQUIRED_FLAGS, config)

        app_version = na_utils.OpenStackInfo().info()
        LOG.info('OpenStack OS Version Info: %s', app_version)
        kwargs['app_version'] = app_version

        driver_mode = NetAppDriver._get_driver_mode(
            config.netapp_storage_family, config.driver_handles_share_servers)

        return NetAppDriver._create_driver(config.netapp_storage_family,
                                           driver_mode,
                                           *args, **kwargs)

    @staticmethod
    def _get_driver_mode(storage_family, driver_handles_share_servers):

        if driver_handles_share_servers is None:
            driver_mode = NETAPP_UNIFIED_DRIVER_DEFAULT_MODE.get(
                storage_family.lower())

            if driver_mode:
                LOG.debug('Default driver mode %s selected.', driver_mode)
            else:
                raise exception.InvalidInput(
                    reason=_('Driver mode was not specified and a default '
                             'value could not be determined from the '
                             'specified storage family.'))
        elif driver_handles_share_servers:
            driver_mode = MULTI_SVM
        else:
            driver_mode = SINGLE_SVM

        return driver_mode

    @staticmethod
    def _create_driver(storage_family, driver_mode, *args, **kwargs):
        """"Creates an appropriate driver based on family and mode."""

        storage_family = storage_family.lower()

        fmt = {'storage_family': storage_family, 'driver_mode': driver_mode}
        LOG.info('Requested unified config: %(storage_family)s and '
                 '%(driver_mode)s.', fmt)

        family_meta = NETAPP_UNIFIED_DRIVER_REGISTRY.get(storage_family)
        if family_meta is None:
            raise exception.InvalidInput(
                reason=_('Storage family %s is not supported.')
                % storage_family)

        driver_loc = family_meta.get(driver_mode)
        if driver_loc is None:
            raise exception.InvalidInput(
                reason=_('Driver mode %(driver_mode)s is not supported '
                         'for storage family %(storage_family)s.') % fmt)

        kwargs['netapp_mode'] = 'proxy'
        driver = importutils.import_object(driver_loc, *args, **kwargs)
        LOG.info('NetApp driver of family %(storage_family)s and mode '
                 '%(driver_mode)s loaded.', fmt)
        driver.ipv6_implemented = True
        return driver
