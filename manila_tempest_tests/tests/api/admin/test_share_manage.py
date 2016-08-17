# Copyright 2015 Mirantis Inc.
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

import six
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
import testtools
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class ManageNFSShareTest(base.BaseSharesAdminTest):
    protocol = 'nfs'

    # NOTE(vponomaryov): be careful running these tests using generic driver
    # because cinder volumes will stay attached to service Nova VM and
    # won't be deleted.

    @classmethod
    @testtools.skipIf(
        CONF.share.multitenancy_enabled,
        "Only for driver_handles_share_servers = False driver mode.")
    @testtools.skipUnless(
        CONF.share.run_manage_unmanage_tests,
        "Manage/unmanage tests are disabled.")
    def resource_setup(cls):
        super(ManageNFSShareTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)

        # Create share types
        cls.st_name = data_utils.rand_name("manage-st-name")
        cls.st_name_invalid = data_utils.rand_name("manage-st-name-invalid")
        cls.extra_specs = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': False,
            'snapshot_support': six.text_type(
                CONF.share.capability_snapshot_support),
            'create_share_from_snapshot_support': six.text_type(
                CONF.share.capability_create_share_from_snapshot_support)
        }
        cls.extra_specs_invalid = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': True,
            'snapshot_support': six.text_type(
                CONF.share.capability_snapshot_support),
            'create_share_from_snapshot_support': six.text_type(
                CONF.share.capability_create_share_from_snapshot_support),
        }

        cls.st = cls.create_share_type(
            name=cls.st_name,
            cleanup_in_class=True,
            extra_specs=cls.extra_specs)

        cls.st_invalid = cls.create_share_type(
            name=cls.st_name_invalid,
            cleanup_in_class=True,
            extra_specs=cls.extra_specs_invalid)

    def _test_manage(self, is_public=False,
                     version=CONF.share.max_api_microversion,
                     check_manage=False):

        share = self._create_share_for_manage()

        name = "Name for 'managed' share that had ID %s" % share['id']
        description = "Description for 'managed' share"

        # Unmanage share
        self._unmanage_share_and_wait(share)

        if check_manage:
            # After 'unmanage' operation, share instance should be deleted.
            # Assert not related to 'manage' test, but placed here for
            # resource optimization.
            share_instance_list = self.shares_v2_client.list_share_instances()
            share_ids = [si['share_id'] for si in share_instance_list]
            self.assertNotIn(share['id'], share_ids)

        # Manage share
        managed_share = self.shares_v2_client.manage_share(
            service_host=share['host'],
            export_path=share['export_locations'][0],
            protocol=share['share_proto'],
            share_type_id=self.st['share_type']['id'],
            name=name,
            description=description,
            is_public=is_public,
            version=version,
        )

        # Add managed share to cleanup queue
        self.method_resources.insert(
            0, {'type': 'share', 'id': managed_share['id'],
                'client': self.shares_client})

        # Wait for success
        self.shares_v2_client.wait_for_share_status(managed_share['id'],
                                                    'available')

        # Verify data of managed share
        self.assertEqual(name, managed_share['name'])
        self.assertEqual(description, managed_share['description'])
        self.assertEqual(share['host'], managed_share['host'])
        self.assertEqual(share['share_proto'], managed_share['share_proto'])

        if utils.is_microversion_ge(version, "2.6"):
            self.assertEqual(self.st['share_type']['id'],
                             managed_share['share_type'])
        else:
            self.assertEqual(self.st['share_type']['name'],
                             managed_share['share_type'])

        if utils.is_microversion_ge(version, "2.8"):
            self.assertEqual(is_public, managed_share['is_public'])
        else:
            self.assertFalse(managed_share['is_public'])

        if utils.is_microversion_ge(version, "2.16"):
            self.assertEqual(share['user_id'], managed_share['user_id'])
        else:
            self.assertNotIn('user_id', managed_share)

        # Delete share
        self.shares_v2_client.delete_share(managed_share['id'])
        self.shares_v2_client.wait_for_resource_deletion(
            share_id=managed_share['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_share,
                          managed_share['id'])

    def _create_share_for_manage(self):
        creation_data = {
            'share_type_id': self.st['share_type']['id'],
            'share_protocol': self.protocol,
        }

        share = self.create_share(**creation_data)
        share = self.shares_v2_client.get_share(share['id'])

        if utils.is_microversion_ge(CONF.share.max_api_microversion, "2.9"):
            el = self.shares_v2_client.list_share_export_locations(share["id"])
            share["export_locations"] = el

        return share

    def _unmanage_share_and_wait(self, share):
        self.shares_v2_client.unmanage_share(share['id'])
        self.shares_v2_client.wait_for_resource_deletion(share_id=share['id'])

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.5")
    def test_manage_with_os_share_manage_url(self):
        self._test_manage(version="2.5")

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.8")
    def test_manage_with_is_public_True(self):
        self._test_manage(is_public=True, version="2.8")

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.16")
    def test_manage_show_user_id(self):
        self._test_manage(version="2.16")

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    def test_manage(self):
        self._test_manage(check_manage=True)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    def test_manage_invalid(self):
        # Try to manage share with invalid parameters, it should not succeed
        # because the scheduler will reject it. If it succeeds, then this test
        # case failed. Then, in order to remove the resource from backend, we
        # need to manage it again, properly, so we can delete it. Consequently
        # the second part of this test also tests that manage operation with a
        # proper share type works.

        def _delete_share(share_id):
            self.shares_v2_client.reset_state(share_id)
            self.shares_v2_client.delete_share(share_id)
            self.shares_v2_client.wait_for_resource_deletion(share_id=share_id)
            self.assertRaises(lib_exc.NotFound,
                              self.shares_v2_client.get_share,
                              share_id)

        share = self._create_share_for_manage()

        self._unmanage_share_and_wait(share)

        managed_share = self.shares_v2_client.manage_share(
            service_host=share['host'],
            export_path=share['export_locations'][0],
            protocol=share['share_proto'],
            share_type_id=self.st_invalid['share_type']['id'])
        self.addCleanup(_delete_share, managed_share['id'])

        self.shares_v2_client.wait_for_share_status(
            managed_share['id'], 'manage_error')
        managed_share = self.shares_v2_client.get_share(managed_share['id'])
        self.assertEqual(1, int(managed_share['size']))

        # Delete resource from backend. We need to manage the share properly
        # so it can be removed.
        managed_share = self.shares_v2_client.manage_share(
            service_host=share['host'],
            export_path=share['export_locations'][0],
            protocol=share['share_proto'],
            share_type_id=self.st['share_type']['id'])
        self.addCleanup(_delete_share, managed_share['id'])

        self.shares_v2_client.wait_for_share_status(
            managed_share['id'], 'available')


class ManageCIFSShareTest(ManageNFSShareTest):
    protocol = 'cifs'


class ManageGLUSTERFSShareTest(ManageNFSShareTest):
    protocol = 'glusterfs'


class ManageHDFSShareTest(ManageNFSShareTest):
    protocol = 'hdfs'


class ManageCephFSShareTest(ManageNFSShareTest):
    protocol = 'cephfs'
