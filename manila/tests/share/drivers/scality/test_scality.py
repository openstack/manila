# Copyright (c) 2015 Scality
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

import mock
from oslo_config import cfg
from oslo_concurrency import processutils

from manila import context, exception, test
from manila.share import configuration
from manila.share.drivers.scality import driver
from manila.tests import fake_share

CONF = cfg.CONF


class ScalityShareDriverTestCase(test.TestCase):
    """Test of the main interface of the scality share driver."""

    def setUp(self):
        super(ScalityShareDriverTestCase, self).setUp()

        self.context = context.get_admin_context()

        CONF.set_default('driver_handles_share_servers', False)
        self.config = configuration.Configuration(None)
        self.config.export_management_host = 'host'
        self.config.management_user = 'scality'
        self.config.export_ip = '10.0.0.0/24'

        self.driver = driver.ScalityShareDriver(configuration=self.config)

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_setup(self, management_call):
        self.driver.check_for_setup_error()
        management_call.assert_called_once_with('check')

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_ensure_share_success(self, management_call):
        share = fake_share.fake_share(share_proto='NFS')
        location = '%s:/%s' % (self.config.export_ip, share['id'])
        self.assertEqual(self.driver.ensure_share(self.context, share),
                         location)
        management_call.assert_called_once_with('get %s' % share['id'])

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_ensure_share_failure(self, management_call):
        share = fake_share.fake_share(share_proto='NFS')
        # Test ensure of an unknown share
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.ScalityShareDriver.EXPORT_NOT_FOUND)
        self.assertRaises(exception.InvalidShare,
                          self.driver.ensure_share, self.context, share)

        # Check that unhandled errors are re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.driver.ensure_share, self.context, share)

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_create_share_success(self, management_call):
        share = fake_share.fake_share(share_proto='NFS')
        location = '%s:/%s' % (self.config.export_ip, share['id'])
        self.assertEqual(self.driver.create_share(self.context, share),
                         location)
        management_call.assert_called_once_with('create %s' % share['id'])

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_create_share_failure(self, management_call):
        cifs_share = fake_share.fake_share(share_proto='CIFS')

        self.assertRaises(exception.InvalidInput,
                          self.driver.create_share, self.context, cifs_share)

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_allow_access_success(self, management_call):
        access_to = '192.168.0.1/24'
        access_level = 'rw'
        access = fake_share.fake_access(
            access_to=access_to,
            access_level=access_level,
        )
        share = fake_share.fake_share(share_proto='NFS')

        self.driver.allow_access(self.context, share, access)
        management_call.assert_called_once_with(
            'grant %s %s %s' % (share['id'], access_to, access_level)
        )

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_allow_access_failure(self, management_call):
        access = fake_share.fake_access(access_type='user')
        share = fake_share.fake_share(share_proto='NFS')

        # Unsupported access type
        self.assertRaises(exception.ManilaException, self.driver.allow_access,
                          self.context, share, access)

        # Access is already defined
        access = fake_share.fake_access()
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.ScalityShareDriver.ACCESS_EXISTS
        )
        self.assertRaises(exception.ShareAccessExists, self.driver.allow_access,
                          self.context, share, access)

        # Share does not exist
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.ScalityShareDriver.EXPORT_NOT_FOUND
        )
        self.assertRaises(exception.InvalidShare, self.driver.allow_access,
                          self.context, share, access)

        # Unhandled error code should have the exception re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.driver.allow_access, self.context, share, access)

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_deny_access_success(self, management_call):
        access = fake_share.fake_access()
        share = fake_share.fake_share(share_proto='NFS')

        self.driver.deny_access(self.context, share, access)
        management_call.assert_called_once_with(
            'revoke %s %s' % (share['id'], access['access_to'])
        )

    @mock.patch.object(driver.ScalityShareDriver, '_management_call')
    def test_deny_access_failure(self, management_call):
        access = fake_share.fake_access(access_type='user')
        share = fake_share.fake_share(share_proto='NFS')

        # Unsupported access type
        self.assertRaises(exception.ManilaException, self.driver.deny_access,
                          self.context, share, access)

        # Access does not exist
        access = fake_share.fake_access()
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.ScalityShareDriver.ACCESS_NOT_FOUND
        )
        self.assertRaises(exception.InvalidShareAccess, self.driver.deny_access,
                          self.context, share, access)

        # Share does not exist
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.ScalityShareDriver.EXPORT_NOT_FOUND
        )
        self.assertRaises(exception.InvalidShare, self.driver.deny_access,
                          self.context, share, access)

        # Unhandled error code should have the exception re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.driver.deny_access, self.context, share, access)

    def test_update_share_stats(self):
        # NFS support should be published
        self.driver.get_share_stats(refresh=True)
        self.assertEqual(self.driver._stats['storage_protocol'], 'NFS')
