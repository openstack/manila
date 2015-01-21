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
from manila.share.drivers.netapp import cluster_mode
from manila.share.drivers.netapp import common as na_common
from manila import test
from manila.tests.share.drivers.netapp import fakes as na_fakes


class NetAppDriverFactoryTestCase(test.TestCase):

    def setUp(self):
        super(NetAppDriverFactoryTestCase, self).setUp()
        self.mock_object(na_common, 'LOG')

    def test_new(self):

        mock_create_driver = self.mock_object(na_common.NetAppDriver,
                                              'create_driver')

        config = na_fakes.create_configuration()
        config.netapp_storage_family = 'fake_family'
        config.driver_handles_share_servers = True

        kwargs = {'configuration': config}
        na_common.NetAppDriver(**kwargs)

        mock_create_driver.assert_called_with('fake_family', True,
                                              *(), **kwargs)

    def test_new_missing_config(self):

        self.mock_object(na_common.NetAppDriver, 'create_driver')

        self.assertRaises(exception.InvalidInput, na_common.NetAppDriver, **{})

    def test_new_missing_family(self):

        self.mock_object(na_common.NetAppDriver, 'create_driver')

        config = na_fakes.create_configuration()
        config.driver_handles_share_servers = True
        config.netapp_storage_family = None

        kwargs = {'configuration': config}
        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver,
                          **kwargs)

    def test_new_missing_mode(self):

        config = na_fakes.create_configuration()
        config.driver_handles_share_servers = None
        config.netapp_storage_family = 'fake_family'

        kwargs = {'configuration': config}
        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver,
                          **kwargs)

    def test_create_driver(self):

        def get_full_class_name(obj):
            return obj.__module__ + '.' + obj.__class__.__name__

        config = na_fakes.create_configuration()
        config.local_conf.set_override('driver_handles_share_servers', True)

        kwargs = {'configuration': config}

        registry = na_common.NETAPP_UNIFIED_DRIVER_REGISTRY
        mock_db = mock.Mock()

        for family in six.iterkeys(registry):
            for mode, full_class_name in six.iteritems(registry[family]):
                driver = na_common.NetAppDriver.create_driver(
                    family, mode, mock_db, **kwargs)
                self.assertEqual(full_class_name, get_full_class_name(driver))

    def test_create_driver_case_insensitive(self):

        config = na_fakes.create_configuration()
        config.local_conf.set_override('driver_handles_share_servers', True)

        kwargs = {'configuration': config}

        mock_db = mock.Mock()

        driver = na_common.NetAppDriver.create_driver('ONTAP_CLUSTER',
                                                      True,
                                                      mock_db,
                                                      **kwargs)

        self.assertIsInstance(driver,
                              cluster_mode.NetAppClusteredShareDriver)

    def test_create_driver_invalid_family(self):

        kwargs = {'configuration': na_fakes.create_configuration()}
        mock_db = mock.Mock()

        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver.create_driver,
                          'fake_family', 'iscsi', mock_db, **kwargs)

    def test_create_driver_missing_mode_good_default(self):

        config = na_fakes.create_configuration()
        config.local_conf.set_override('driver_handles_share_servers', True)

        kwargs = {'configuration': config}
        mock_db = mock.Mock()

        driver = na_common.NetAppDriver.create_driver('ONTAP_CLUSTER',
                                                      None,
                                                      mock_db,
                                                      **kwargs)

        self.assertIsInstance(driver,
                              cluster_mode.NetAppClusteredShareDriver)

    def test_create_driver_missing_mode_no_default(self):

        kwargs = {'configuration': na_fakes.create_configuration()}
        mock_db = mock.Mock()

        self.assertRaises(exception.InvalidInput,
                          na_common.NetAppDriver.create_driver,
                          'fake_family', None, mock_db, **kwargs)
