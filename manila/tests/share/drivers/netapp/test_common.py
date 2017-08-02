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

import mock
import six

from manila import exception
from manila.share.drivers.netapp import common as na_common
from manila.share.drivers.netapp.dataontap.cluster_mode import drv_multi_svm
from manila.share.drivers.netapp import utils as na_utils
from manila import test
from manila.tests.share.drivers.netapp import fakes as na_fakes


class NetAppDriverFactoryTestCase(test.TestCase):

    def test_new(self):

        self.mock_object(na_utils.OpenStackInfo, 'info',
                         mock.Mock(return_value='fake_info'))
        mock_get_driver_mode = self.mock_object(
            na_common.NetAppDriver, '_get_driver_mode',
            mock.Mock(return_value='fake_mode'))
        mock_create_driver = self.mock_object(na_common.NetAppDriver,
                                              '_create_driver')

        config = na_fakes.create_configuration()
        config.netapp_storage_family = 'fake_family'
        config.driver_handles_share_servers = True

        kwargs = {'configuration': config}
        na_common.NetAppDriver(**kwargs)

        kwargs['app_version'] = 'fake_info'
        mock_get_driver_mode.assert_called_once_with('fake_family', True)
        mock_create_driver.assert_called_once_with('fake_family', 'fake_mode',
                                                   *(), **kwargs)

    def test_new_missing_config(self):

        self.mock_object(na_utils.OpenStackInfo, 'info')
        self.mock_object(na_common.NetAppDriver, '_create_driver')

        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver, **{})

    def test_new_missing_family(self):

        self.mock_object(na_utils.OpenStackInfo, 'info')
        self.mock_object(na_common.NetAppDriver, '_create_driver')

        config = na_fakes.create_configuration()
        config.driver_handles_share_servers = True
        config.netapp_storage_family = None

        kwargs = {'configuration': config}
        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver,
                          **kwargs)

    def test_new_missing_mode(self):

        self.mock_object(na_utils.OpenStackInfo, 'info')
        self.mock_object(na_common.NetAppDriver, '_create_driver')

        config = na_fakes.create_configuration()
        config.driver_handles_share_servers = None
        config.netapp_storage_family = 'fake_family'

        kwargs = {'configuration': config}
        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver,
                          **kwargs)

    def test_get_driver_mode_missing_mode_good_default(self):

        result = na_common.NetAppDriver._get_driver_mode('ONTAP_CLUSTER', None)
        self.assertEqual(na_common.MULTI_SVM, result)

    def test_create_driver_missing_mode_no_default(self):

        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver._get_driver_mode,
                          'fake_family', None)

    def test_get_driver_mode_multi_svm(self):

        result = na_common.NetAppDriver._get_driver_mode('ONTAP_CLUSTER', True)
        self.assertEqual(na_common.MULTI_SVM, result)

    def test_get_driver_mode_single_svm(self):

        result = na_common.NetAppDriver._get_driver_mode('ONTAP_CLUSTER',
                                                         False)
        self.assertEqual(na_common.SINGLE_SVM, result)

    def test_create_driver(self):

        def get_full_class_name(obj):
            return obj.__module__ + '.' + obj.__class__.__name__

        registry = na_common.NETAPP_UNIFIED_DRIVER_REGISTRY

        for family in six.iterkeys(registry):
            for mode, full_class_name in registry[family].items():

                config = na_fakes.create_configuration()
                config.local_conf.set_override('driver_handles_share_servers',
                                               mode == na_common.MULTI_SVM)
                kwargs = {
                    'configuration': config,
                    'private_storage': mock.Mock(),
                    'app_version': 'fake_info'
                }

                driver = na_common.NetAppDriver._create_driver(
                    family, mode, **kwargs)

                self.assertEqual(full_class_name, get_full_class_name(driver))

    def test_create_driver_case_insensitive(self):

        config = na_fakes.create_configuration()
        config.local_conf.set_override('driver_handles_share_servers', True)

        kwargs = {
            'configuration': config,
            'private_storage': mock.Mock(),
            'app_version': 'fake_info'
        }

        driver = na_common.NetAppDriver._create_driver('ONTAP_CLUSTER',
                                                       na_common.MULTI_SVM,
                                                       **kwargs)

        self.assertIsInstance(driver,
                              drv_multi_svm.NetAppCmodeMultiSvmShareDriver)

    def test_create_driver_invalid_family(self):

        kwargs = {
            'configuration': na_fakes.create_configuration(),
            'app_version': 'fake_info',
        }

        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver._create_driver,
                          'fake_family', na_common.MULTI_SVM,
                          **kwargs)

    def test_create_driver_invalid_mode(self):

        kwargs = {
            'configuration': na_fakes.create_configuration(),
            'app_version': 'fake_info',
        }

        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver._create_driver,
                          'ontap_cluster', 'fake_mode', **kwargs)
