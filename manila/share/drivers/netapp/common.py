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

from oslo_utils import importutils

from manila import exception
from manila.i18n import _, _LI
from manila.openstack.common import log as logging
from manila.share import driver
from manila.share.drivers.netapp import cluster_mode
from manila.share.drivers.netapp import utils as na_utils


LOG = logging.getLogger(__name__)

# Add new drivers here, no other code changes required.
NETAPP_UNIFIED_DRIVER_REGISTRY = {
    'ontap_cluster':
    {
        'multi_svm':
        'manila.share.drivers.netapp.cluster_mode.NetAppClusteredShareDriver',
    }
}
NETAPP_UNIFIED_DRIVER_DEFAULT_MODE = {
    'ontap_cluster': 'multi_svm',
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
                reason=_('Required configuration not found'))

        config.append_config_values(driver.share_opts)
        config.append_config_values(cluster_mode.NETAPP_NAS_OPTS)
        na_utils.check_flags(NetAppDriver.REQUIRED_FLAGS, config)

        return NetAppDriver.create_driver(config.netapp_storage_family,
                                          config.driver_handles_share_servers,
                                          *args, **kwargs)

    @staticmethod
    def create_driver(storage_family, driver_handles_share_servers, *args,
                      **kwargs):
        """"Creates an appropriate driver based on family and mode."""

        storage_family = storage_family.lower()

        # determine driver mode
        if driver_handles_share_servers is None:
            driver_mode = NETAPP_UNIFIED_DRIVER_DEFAULT_MODE.get(
                storage_family)

            if driver_mode:
                LOG.debug('Default driver mode %s selected.' % driver_mode)
            else:
                raise exception.InvalidInput(
                    reason=_('Driver mode was not specified and a default '
                             'value could not be determined from the '
                             'specified storage family'))
        elif driver_handles_share_servers:
            driver_mode = 'multi_svm'
        else:
            driver_mode = 'single_svm'

        fmt = {'storage_family': storage_family,
               'driver_mode': driver_mode}
        LOG.info(_LI('Requested unified config: %(storage_family)s and '
                     '%(driver_mode)s.') % fmt)

        family_meta = NETAPP_UNIFIED_DRIVER_REGISTRY.get(storage_family)
        if family_meta is None:
            raise exception.InvalidInput(
                reason=_('Storage family %s is not supported')
                % storage_family)

        driver_loc = family_meta.get(driver_mode)
        if driver_loc is None:
            raise exception.InvalidInput(
                reason=_('Driver mode %(driver_mode)s is not supported '
                         'for storage family %(storage_family)s') % fmt)

        kwargs = kwargs or {}
        kwargs['netapp_mode'] = 'proxy'
        driver = importutils.import_object(driver_loc, *args, **kwargs)
        LOG.info(_LI('NetApp driver of family %(storage_family)s and mode '
                     '%(driver_mode)s loaded.') % fmt)
        return driver
