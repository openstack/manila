# Copyright 2015 Andrew Kerr
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

from tempest import config
from tempest import test
from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions
import testtools

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@testtools.skipUnless(CONF.share.run_consistency_group_tests,
                      'Consistency Group tests disabled.')
class ConsistencyGroupsNegativeTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ConsistencyGroupsNegativeTest, cls).resource_setup()
        # Create share_type
        name = data_utils.rand_name("tempest-manila")
        extra_specs = cls.add_required_extra_specs_to_dict()
        share_type = cls.create_share_type(name, extra_specs=extra_specs)
        cls.share_type = share_type['share_type']

        # Create a consistency group
        cls.consistency_group = cls.create_consistency_group(
            share_type_ids=[cls.share_type['id']])

        # Create share inside consistency group
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        cls.share = cls.create_share(
            name=cls.share_name,
            description=cls.share_desc,
            size=cls.share_size,
            consistency_group_id=cls.consistency_group['id'],
            share_type_id=cls.share_type['id'],
            client=cls.shares_v2_client,
        )

        # Create a cgsnapshot of the consistency group
        cls.cgsnap_name = data_utils.rand_name("tempest-cgsnap-name")
        cls.cgsnap_desc = data_utils.rand_name("tempest-cgsnap-description")
        cls.cgsnapshot = cls.create_cgsnapshot_wait_for_active(
            cls.consistency_group["id"],
            name=cls.cgsnap_name,
            description=cls.cgsnap_desc)

    @test.attr(type=["negative", "gate", ])
    def test_delete_share_type_in_use_by_cg(self):
        # Attempt delete of share type
        self.assertRaises(exceptions.BadRequest,
                          self.shares_client.delete_share_type,
                          self.share_type['id'])

    @test.attr(type=["negative", "gate", ])
    def test_create_share_of_unsupported_type_in_cg_v2_4(self):
        # Attempt to create share of default type in the cg
        self.assertRaises(exceptions.BadRequest,
                          self.create_share,
                          size=1,
                          consistency_group_id=self.consistency_group['id'],
                          client=self.shares_v2_client,
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_create_share_in_cg_that_is_not_available_v2_4(self):
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False, version='2.4')
        self.addCleanup(self.shares_v2_client.consistency_group_reset_state,
                        consistency_group['id'],
                        status='available',
                        version='2.4')
        # creating
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='creating', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'creating')
        self.assertRaises(exceptions.BadRequest, self.create_share,
                          name=self.share_name,
                          description=self.share_desc,
                          size=self.share_size,
                          consistency_group_id=consistency_group['id'],
                          cleanup_in_class=False,
                          client=self.shares_v2_client,
                          version='2.4')
        # deleting
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='deleting', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'deleting')
        self.assertRaises(exceptions.BadRequest, self.create_share,
                          name=self.share_name,
                          description=self.share_desc,
                          size=self.share_size,
                          consistency_group_id=consistency_group['id'],
                          cleanup_in_class=False,
                          client=self.shares_v2_client,
                          version='2.4')
        # error
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='error', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'error')
        self.assertRaises(exceptions.BadRequest, self.create_share,
                          name=self.share_name,
                          description=self.share_desc,
                          size=self.share_size,
                          consistency_group_id=consistency_group['id'],
                          cleanup_in_class=False,
                          client=self.shares_v2_client,
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_create_cgsnapshot_of_cg_that_is_not_available_v2_4(self):
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False, version='2.4')
        self.addCleanup(self.shares_v2_client.consistency_group_reset_state,
                        consistency_group['id'],
                        status='available',
                        version='2.4')
        # creating
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='creating', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'creating')
        self.assertRaises(exceptions.Conflict,
                          self.create_cgsnapshot_wait_for_active,
                          consistency_group['id'],
                          cleanup_in_class=False,
                          version='2.4')
        # deleting
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='deleting', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'deleting')
        self.assertRaises(exceptions.Conflict,
                          self.create_cgsnapshot_wait_for_active,
                          consistency_group['id'],
                          cleanup_in_class=False,
                          version='2.4')
        # error
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='error', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'error')
        self.assertRaises(exceptions.Conflict,
                          self.create_cgsnapshot_wait_for_active,
                          consistency_group['id'],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_create_cgsnapshot_of_cg_with_share_in_error_state_v2_4(self):
        consistency_group = self.create_consistency_group(version='2.4')
        share_name = data_utils.rand_name("tempest-share-name")
        share_desc = data_utils.rand_name("tempest-share-description")
        share_size = 1
        share = self.create_share(
            name=share_name,
            description=share_desc,
            size=share_size,
            consistency_group_id=consistency_group['id'],
            cleanup_in_class=False,
            client=self.shares_v2_client,
            version='2.4',
        )
        self.shares_client.reset_state(s_id=share['id'])
        self.shares_client.wait_for_share_status(share['id'], 'error')
        self.assertRaises(exceptions.Conflict,
                          self.create_cgsnapshot_wait_for_active,
                          consistency_group['id'],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_delete_cgsnapshot_not_in_available_or_error_v2_4(self):
        cgsnapshot = self.create_cgsnapshot_wait_for_active(
            self.consistency_group['id'],
            cleanup_in_class=False,
            version='2.4',
        )
        self.addCleanup(self.shares_v2_client.cgsnapshot_reset_state,
                        cgsnapshot['id'],
                        status='available',
                        version='2.4')

        # creating
        self.shares_v2_client.cgsnapshot_reset_state(cgsnapshot['id'],
                                                     status='creating',
                                                     version='2.4')
        self.shares_v2_client.wait_for_cgsnapshot_status(cgsnapshot['id'],
                                                         'creating')
        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.delete_cgsnapshot,
                          cgsnapshot['id'],
                          version='2.4')
        # deleting
        self.shares_v2_client.cgsnapshot_reset_state(cgsnapshot['id'],
                                                     status='deleting',
                                                     version='2.4')
        self.shares_v2_client.wait_for_cgsnapshot_status(cgsnapshot['id'],
                                                         'deleting')
        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.delete_cgsnapshot,
                          cgsnapshot['id'],
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_delete_cg_not_in_available_or_error_v2_4(self):
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False, version='2.4')
        self.addCleanup(self.shares_v2_client.consistency_group_reset_state,
                        consistency_group['id'],
                        status='available',
                        version='2.4')
        # creating
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='creating', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'creating')
        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.delete_consistency_group,
                          consistency_group['id'],
                          version='2.4')
        # deleting
        self.shares_v2_client.consistency_group_reset_state(
            consistency_group['id'], status='deleting', version='2.4')
        self.shares_v2_client.wait_for_consistency_group_status(
            consistency_group['id'], 'deleting')
        self.assertRaises(exceptions.Conflict,
                          self.shares_v2_client.delete_consistency_group,
                          consistency_group['id'],
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_create_cg_with_conflicting_share_types_v2_4(self):
        # Create conflicting share types
        name = data_utils.rand_name("tempest-manila")
        extra_specs = {"driver_handles_share_servers": False}
        share_type = self.create_share_type(name, extra_specs=extra_specs)
        single_tenant_share_type = share_type['share_type']

        name = data_utils.rand_name("tempest-manila")
        extra_specs = {"driver_handles_share_servers": True}
        share_type = self.create_share_type(name, extra_specs=extra_specs)
        multi_tenant_share_type = share_type['share_type']

        self.assertRaises(exceptions.BadRequest,
                          self.create_consistency_group,
                          share_type_ids=[single_tenant_share_type['id'],
                                          multi_tenant_share_type['id']],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_create_cg_with_multi_tenant_share_type_and_no_share_network_v2_4(
            self):
        # Create multi tenant share type
        name = data_utils.rand_name("tempest-manila")
        extra_specs = {"driver_handles_share_servers": True}
        share_type = self.create_share_type(name, extra_specs=extra_specs)
        multi_tenant_share_type = share_type['share_type']

        def create_cg():
            cg = self.shares_v2_client.create_consistency_group(
                share_type_ids=[multi_tenant_share_type['id']],
                version='2.4'
            )
            resource = {
                "type": "consistency_group",
                "id": cg["id"],
                "client": self.shares_client
            }
            self.method_resources.insert(0, resource)
            return cg

        self.assertRaises(exceptions.BadRequest, create_cg)

    @test.attr(type=["negative", "gate", ])
    def test_update_cg_share_types(self):
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False, version='2.4')

        self.assertRaises(exceptions.BadRequest,
                          self.shares_v2_client.update_consistency_group,
                          consistency_group['id'],
                          share_types=[self.share_type['id']],
                          version='2.4')
