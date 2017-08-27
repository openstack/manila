# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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
Mock unit tests for the NetApp driver utility module
"""

import platform

import ddt
import mock
from oslo_concurrency import processutils as putils
from oslo_log import log

from manila import exception
from manila.share.drivers.netapp import utils as na_utils
from manila import test
from manila import version


@ddt.ddt
class NetAppDriverUtilsTestCase(test.TestCase):

    def setUp(self):
        super(NetAppDriverUtilsTestCase, self).setUp()

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(na_utils.LOG,
                         'warning',
                         mock.Mock(side_effect=mock_logger.warning))
        self.mock_object(na_utils.LOG,
                         'debug',
                         mock.Mock(side_effect=mock_logger.debug))

        na_utils.setup_tracing(None)

    def test_round_down(self):
        self.assertAlmostEqual(na_utils.round_down(5.567), 5.56)
        self.assertAlmostEqual(na_utils.round_down(5.567, '0.00'), 5.56)
        self.assertAlmostEqual(na_utils.round_down(5.567, '0.0'), 5.5)
        self.assertAlmostEqual(na_utils.round_down(5.567, '0'), 5)
        self.assertAlmostEqual(na_utils.round_down(0, '0.00'), 0)
        self.assertAlmostEqual(na_utils.round_down(-5.567), -5.56)
        self.assertAlmostEqual(na_utils.round_down(-5.567, '0.00'), -5.56)
        self.assertAlmostEqual(na_utils.round_down(-5.567, '0.0'), -5.5)
        self.assertAlmostEqual(na_utils.round_down(-5.567, '0'), -5)

    def test_setup_tracing(self):
        na_utils.setup_tracing(None, api_trace_pattern='(.*)')
        self.assertFalse(na_utils.TRACE_API)
        self.assertFalse(na_utils.TRACE_METHOD)
        self.assertEqual('(.*)', na_utils.API_TRACE_PATTERN)
        self.assertEqual(0, na_utils.LOG.warning.call_count)

        na_utils.setup_tracing('method')
        self.assertFalse(na_utils.TRACE_API)
        self.assertTrue(na_utils.TRACE_METHOD)
        self.assertEqual('(.*)', na_utils.API_TRACE_PATTERN)
        self.assertEqual(0, na_utils.LOG.warning.call_count)

        na_utils.setup_tracing('method,api', api_trace_pattern='(^fancy-api$)')
        self.assertTrue(na_utils.TRACE_API)
        self.assertTrue(na_utils.TRACE_METHOD)
        self.assertEqual('(^fancy-api$)', na_utils.API_TRACE_PATTERN)
        self.assertEqual(0, na_utils.LOG.warning.call_count)

    def test_setup_tracing_invalid_key(self):
        na_utils.setup_tracing('method,fake')

        self.assertFalse(na_utils.TRACE_API)
        self.assertTrue(na_utils.TRACE_METHOD)
        self.assertEqual(1, na_utils.LOG.warning.call_count)

    @ddt.data('?!(bad', '(reg]+', 'eX?!)')
    def test_setup_tracing_invalid_regex(self, regex):
        self.assertRaises(exception.BadConfigurationException,
                          na_utils.setup_tracing, 'method,api',
                          api_trace_pattern=regex)

    @na_utils.trace
    def _trace_test_method(*args, **kwargs):
        return 'OK'

    def test_trace_no_tracing(self):
        result = self._trace_test_method()

        self.assertEqual('OK', result)
        self.assertEqual(0, na_utils.LOG.debug.call_count)

        na_utils.setup_tracing('method')

    def test_trace_method_tracing(self):
        na_utils.setup_tracing('method')

        result = self._trace_test_method()
        self.assertEqual('OK', result)
        self.assertEqual(2, na_utils.LOG.debug.call_count)

    def test_validate_driver_instantiation_proxy(self):
        kwargs = {'netapp_mode': 'proxy'}

        na_utils.validate_driver_instantiation(**kwargs)

        self.assertEqual(0, na_utils.LOG.warning.call_count)

    def test_validate_driver_instantiation_no_proxy(self):
        kwargs = {'netapp_mode': 'asdf'}

        na_utils.validate_driver_instantiation(**kwargs)

        self.assertEqual(1, na_utils.LOG.warning.call_count)

    def test_check_flags(self):
        configuration = type('Fake',
                             (object,),
                             {'flag1': 'value1', 'flag2': 'value2'})

        self.assertIsNone(na_utils.check_flags(['flag1', 'flag2'],
                                               configuration))

    def test_check_flags_missing_flag(self):
        configuration = type('Fake',
                             (object,),
                             {'flag1': 'value1', 'flag3': 'value3'})

        self.assertRaises(exception.InvalidInput,
                          na_utils.check_flags,
                          ['flag1', 'flag2'],
                          configuration)

    def test_convert_to_list(self):
        self.assertListEqual([], na_utils.convert_to_list(None))
        self.assertListEqual(['test'], na_utils.convert_to_list('test'))
        self.assertListEqual(['a'], na_utils.convert_to_list(['a']))
        self.assertListEqual(['a', 'b'], na_utils.convert_to_list(['a', 'b']))
        self.assertListEqual([1, 2, 3], na_utils.convert_to_list((1, 2, 3)))
        self.assertListEqual([5], na_utils.convert_to_list(5))
        self.assertListEqual(
            sorted(['key1', 'key2']),
            sorted(na_utils.convert_to_list({'key1': 'value1',
                                             'key2': 'value2'})))


class OpenstackInfoTestCase(test.TestCase):

    UNKNOWN_VERSION = 'unknown version'
    UNKNOWN_RELEASE = 'unknown release'
    UNKNOWN_VENDOR = 'unknown vendor'
    UNKNOWN_PLATFORM = 'unknown platform'
    VERSION_STRING_RET_VAL = 'fake_version_1'
    RELEASE_STRING_RET_VAL = 'fake_release_1'
    PLATFORM_RET_VAL = 'fake_platform_1'
    VERSION_INFO_VERSION = 'fake_version_2'
    VERSION_INFO_RELEASE = 'fake_release_2'
    RPM_INFO_VERSION = 'fake_version_3'
    RPM_INFO_RELEASE = 'fake_release_3'
    RPM_INFO_VENDOR = 'fake vendor 3'
    PUTILS_RPM_RET_VAL = ('fake_version_3  fake_release_3 fake vendor 3', '')
    NO_PKG_FOUND = ('', 'whatever')
    PUTILS_DPKG_RET_VAL = ('epoch:upstream_version-debian_revision', '')
    DEB_RLS = 'upstream_version-debian_revision'
    DEB_VENDOR = 'debian_revision'

    def test_openstack_info_init(self):
        info = na_utils.OpenStackInfo()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(version.version_info, 'version_string',
                       mock.Mock(return_value=VERSION_STRING_RET_VAL))
    def test_update_version_from_version_string(self):
        info = na_utils.OpenStackInfo()
        info._update_version_from_version_string()

        self.assertEqual(self.VERSION_STRING_RET_VAL, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(version.version_info, 'version_string',
                       mock.Mock(side_effect=Exception))
    def test_exception_in_update_version_from_version_string(self):
        info = na_utils.OpenStackInfo()
        info._update_version_from_version_string()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(version.version_info, 'release_string',
                       mock.Mock(return_value=RELEASE_STRING_RET_VAL))
    def test_update_release_from_release_string(self):
        info = na_utils.OpenStackInfo()
        info._update_release_from_release_string()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.RELEASE_STRING_RET_VAL, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(version.version_info, 'release_string',
                       mock.Mock(side_effect=Exception))
    def test_exception_in_update_release_from_release_string(self):
        info = na_utils.OpenStackInfo()
        info._update_release_from_release_string()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(platform, 'platform',
                       mock.Mock(return_value=PLATFORM_RET_VAL))
    def test_update_platform(self):
        info = na_utils.OpenStackInfo()
        info._update_platform()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.PLATFORM_RET_VAL, info._platform)

    @mock.patch.object(platform, 'platform',
                       mock.Mock(side_effect=Exception))
    def test_exception_in_update_platform(self):
        info = na_utils.OpenStackInfo()
        info._update_platform()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(na_utils.OpenStackInfo, '_get_version_info_version',
                       mock.Mock(return_value=VERSION_INFO_VERSION))
    @mock.patch.object(na_utils.OpenStackInfo, '_get_version_info_release',
                       mock.Mock(return_value=VERSION_INFO_RELEASE))
    def test_update_info_from_version_info(self):
        info = na_utils.OpenStackInfo()
        info._update_info_from_version_info()

        self.assertEqual(self.VERSION_INFO_VERSION, info._version)
        self.assertEqual(self.VERSION_INFO_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(na_utils.OpenStackInfo, '_get_version_info_version',
                       mock.Mock(return_value=''))
    @mock.patch.object(na_utils.OpenStackInfo, '_get_version_info_release',
                       mock.Mock(return_value=None))
    def test_no_info_from_version_info(self):
        info = na_utils.OpenStackInfo()
        info._update_info_from_version_info()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(na_utils.OpenStackInfo, '_get_version_info_version',
                       mock.Mock(return_value=VERSION_INFO_VERSION))
    @mock.patch.object(na_utils.OpenStackInfo, '_get_version_info_release',
                       mock.Mock(side_effect=Exception))
    def test_exception_in_info_from_version_info(self):
        info = na_utils.OpenStackInfo()
        info._update_info_from_version_info()

        self.assertEqual(self.VERSION_INFO_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)

    @mock.patch.object(putils, 'execute',
                       mock.Mock(return_value=PUTILS_RPM_RET_VAL))
    def test_update_info_from_rpm(self):
        info = na_utils.OpenStackInfo()
        found_package = info._update_info_from_rpm()

        self.assertEqual(self.RPM_INFO_VERSION, info._version)
        self.assertEqual(self.RPM_INFO_RELEASE, info._release)
        self.assertEqual(self.RPM_INFO_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)
        self.assertTrue(found_package)

    @mock.patch.object(putils, 'execute',
                       mock.Mock(return_value=NO_PKG_FOUND))
    def test_update_info_from_rpm_no_pkg_found(self):
        info = na_utils.OpenStackInfo()
        found_package = info._update_info_from_rpm()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)
        self.assertFalse(found_package)

    @mock.patch.object(putils, 'execute',
                       mock.Mock(side_effect=Exception))
    def test_exception_in_update_info_from_rpm(self):
        info = na_utils.OpenStackInfo()
        found_package = info._update_info_from_rpm()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)
        self.assertFalse(found_package)

    @mock.patch.object(putils, 'execute',
                       mock.Mock(return_value=PUTILS_DPKG_RET_VAL))
    def test_update_info_from_dpkg(self):
        info = na_utils.OpenStackInfo()
        found_package = info._update_info_from_dpkg()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.DEB_RLS, info._release)
        self.assertEqual(self.DEB_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)
        self.assertTrue(found_package)

    @mock.patch.object(putils, 'execute',
                       mock.Mock(return_value=NO_PKG_FOUND))
    def test_update_info_from_dpkg_no_pkg_found(self):
        info = na_utils.OpenStackInfo()
        found_package = info._update_info_from_dpkg()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)
        self.assertFalse(found_package)

    @mock.patch.object(putils, 'execute',
                       mock.Mock(side_effect=Exception))
    def test_exception_in_update_info_from_dpkg(self):
        info = na_utils.OpenStackInfo()
        found_package = info._update_info_from_dpkg()

        self.assertEqual(self.UNKNOWN_VERSION, info._version)
        self.assertEqual(self.UNKNOWN_RELEASE, info._release)
        self.assertEqual(self.UNKNOWN_VENDOR, info._vendor)
        self.assertEqual(self.UNKNOWN_PLATFORM, info._platform)
        self.assertFalse(found_package)

    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_version_from_version_string', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_release_from_release_string', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_platform', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_info_from_version_info', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_info_from_rpm', mock.Mock(return_value=True))
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_info_from_dpkg')
    def test_update_openstack_info_rpm_pkg_found(self, mock_updt_from_dpkg):
        info = na_utils.OpenStackInfo()
        info._update_openstack_info()

        self.assertFalse(mock_updt_from_dpkg.called)

    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_version_from_version_string', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_release_from_release_string', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_platform', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_info_from_version_info', mock.Mock())
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_info_from_rpm', mock.Mock(return_value=False))
    @mock.patch.object(na_utils.OpenStackInfo,
                       '_update_info_from_dpkg')
    def test_update_openstack_info_rpm_pkg_not_found(self,
                                                     mock_updt_from_dpkg):
        info = na_utils.OpenStackInfo()
        info._update_openstack_info()

        self.assertTrue(mock_updt_from_dpkg.called)
