# Copyright 2024 VAST Data Inc.
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

import itertools
import unittest
from unittest import mock

import ddt
import netaddr

import manila.context as manila_context
import manila.exception as exception
from manila.share import configuration
from manila.share.drivers.vastdata import driver
from manila.share.drivers.vastdata import driver_util
from manila.tests import fake_share
from manila.tests.share.drivers.vastdata.test_rest import fake_metrics


@mock.patch(
    "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
    mock.MagicMock()
)
@ddt.ddt
class VASTShareDriverTestCase(unittest.TestCase):
    def _create_mocked_rest_api(self):
        # Create a mock RestApi instance
        mock_rest_api = mock.MagicMock()

        # Create mock sub resources with their methods
        subresources = [
            "views",
            "view_policies",
            "capacity_metrics",
            "quotas",
            "vip_pools",
            "snapshots",
            "folders",
        ]
        methods = [
            "list", "create", "update",
            "delete", "one", "ensure", "vips"
        ]

        for subresource in subresources:
            mock_subresource = mock.MagicMock()
            setattr(mock_rest_api, subresource, mock_subresource)

            for method in methods:
                mock_method = mock.MagicMock()
                setattr(mock_subresource, method, mock_method)

        return mock_rest_api

    @mock.patch(
        "manila.share.drivers.vastdata.rest.Session.refresh_auth_token"
    )
    def setUp(self, m_auth_token):
        super().setUp()
        self.fake_conf = configuration.Configuration(None)
        self._context = manila_context.get_admin_context()
        self._snapshot = fake_share.fake_snapshot_instance()

        self.fake_conf.set_default("driver_handles_share_servers", False)
        self.fake_conf.set_default("share_backend_name", "vast")
        self.fake_conf.set_default("vast_mgmt_host", "test")
        self.fake_conf.set_default("vast_root_export", "/fake")
        self.fake_conf.set_default("vast_vippool_name", "vippool")
        self.fake_conf.set_default("vast_mgmt_user", "user")
        self.fake_conf.set_default("vast_mgmt_password", "password")
        self._driver = driver.VASTShareDriver(
            execute=mock.MagicMock(), configuration=self.fake_conf
        )
        self._driver.do_setup(self._context)
        if self.fake_conf.vast_api_token:
            m_auth_token.assert_not_called()
        else:
            m_auth_token.assert_called_once()

    def test_do_setup(self):
        session = self._driver.rest.session
        self.assertEqual(self._driver._backend_name, "vast")
        self.assertEqual(self._driver._vippool_name, "vippool")
        self.assertEqual(self._driver._root_export, "/fake")
        self.assertFalse(session.ssl_verify)
        self.assertEqual(session.base_url, "https://test:443/api")

    @ddt.data("vast_mgmt_user", "vast_mgmt_host")
    def test_do_setup_missing_required_fields(self, missing_field):
        self.fake_conf.set_default(missing_field, None)
        _driver = driver.VASTShareDriver(
            execute=mock.MagicMock(), configuration=self.fake_conf
        )
        with self.assertRaises(exception.VastDriverException):
            _driver.do_setup(self._context)

    def test_do_setup_with_api_token(self):
        self.fake_conf.set_default("vast_mgmt_user", None)
        self.fake_conf.set_default("vast_mgmt_password", None)
        self.fake_conf.set_default("vast_api_token", "test_token")
        _driver = driver.VASTShareDriver(
            execute=mock.MagicMock(), configuration=self.fake_conf
        )
        _driver.do_setup(self._context)
        self.assertEqual(_driver.rest.session.token, "test_token")

    @mock.patch(
        "manila.share.drivers.vastdata.rest.Session.get",
        mock.MagicMock(return_value=fake_metrics),
    )
    def test_update_share_stats(self):
        self._driver._update_share_stats()
        result = self._driver._stats
        self.assertEqual(result["share_backend_name"], "vast")
        self.assertEqual(result["driver_handles_share_servers"], False)
        self.assertEqual(result["vendor_name"], "VAST STORAGE")
        self.assertEqual(result["driver_version"], "1.1")
        self.assertEqual(result["storage_protocol"], "NFS")
        self.assertEqual(result["total_capacity_gb"], 471.1061706542969)
        self.assertEqual(result["free_capacity_gb"], 450.2256333641708)
        self.assertEqual(result["reserved_percentage"], 0)
        self.assertEqual(result["reserved_snapshot_percentage"], 0)
        self.assertEqual(result["reserved_share_extend_percentage"], 0)
        self.assertIs(result["qos"], False)
        self.assertIsNone(result["pools"])
        self.assertIs(result["snapshot_support"], True)
        self.assertIs(result["create_share_from_snapshot_support"], False)
        self.assertIs(result["revert_to_snapshot_support"], False)
        self.assertIs(result["mount_snapshot_support"], False)
        self.assertIsNone(result["replication_domain"])
        self.assertIsNone(result["filter_function"])
        self.assertIsNone(result["goodness_function"])
        self.assertIs(result["security_service_update_support"], False)
        self.assertIs(result["network_allocation_update_support"], False)
        self.assertIs(result["share_server_multiple_subnet_support"], False)
        self.assertIs(result["mount_point_name_support"], False)
        self.assertEqual(result["data_reduction"], 1.2)
        self.assertEqual(result["provisioned_capacity_gb"], 20.880537290126085)
        self.assertEqual(
            result["share_group_stats"],
            {"consistent_snapshot_support": None}
        )
        self.assertIs(result["ipv4_support"], True)
        self.assertIs(result["ipv6_support"], False)

    @ddt.idata(
        itertools.product(
            [1073741824, 1], ["NFS", "SMB"], ["fakeid", None]
        )
    )
    @ddt.unpack
    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_shares(
            self,
            capacity,
            proto,
            policy,
            mock_get_extra_specs,
    ):
        mock_get_extra_specs.return_value = {}
        share = fake_share.fake_share(share_proto=proto)
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.ensure.return_value = driver_util.Bunch(id=1)
        mock_rest.quotas.ensure.return_value = driver_util.Bunch(
            id=2, hard_limit=capacity
        )
        mock_rest.views.ensure.return_value = driver_util.Bunch(
            id=3, policy=policy
        )
        # Mock vip_pools.one() to return pool with ip_ranges and tenant_id
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            ip_ranges=[["1.1.1.0", "1.1.1.1"]],
            tenant_id=123
        )
        with mock.patch.object(self._driver, "rest", mock_rest):
            if proto != "NFS":
                with self.assertRaises(exception.InvalidShare) as exc:
                    self._driver.create_share(self._context, share)
                self.assertIn(
                    "Invalid NAS protocol supplied",
                    str(exc.exception)
                )
            elif capacity == 1:
                with self.assertRaises(exception.ManilaException) as exc:
                    self._driver.create_share(self._context, share)
                self.assertIn(
                    "Share already exists with different capacity",
                    str(exc.exception)
                )
            else:

                location = self._driver.create_share(self._context, share)
                mock_rest.vip_pools.one.assert_called_once_with(
                    name="vippool",
                    fail_if_missing=True,
                )
                mock_rest.view_policies.ensure.assert_called_once_with(
                    name="fakeid",
                    tenant_id=123,
                )
                mock_rest.quotas.ensure.assert_called_once_with(
                    name="fakeid",
                    path="/fake/manila-fakeid",
                    create_dir=True,
                    hard_limit=capacity,
                    tenant_id=123,
                )
                mock_rest.views.ensure.assert_called_once_with(
                    name="fakeid",
                    path="/fake/manila-fakeid",
                    policy_id=1,
                    tenant_id=123,
                )
                self.assertListEqual(
                    location,
                    [
                        {
                            'path': '1.1.1.0:/fake/manila-fakeid',
                            'is_admin_only': False
                        },
                        {
                            'path': '1.1.1.1:/fake/manila-fakeid',
                            'is_admin_only': False
                        },
                    ]
                )
                if not policy:
                    mock_rest.views.update.assert_called_once_with(
                        3, policy_id=1
                    )
                else:
                    mock_rest.views.update.assert_not_called()

    def test_delete_share(self):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        with mock.patch.object(self._driver, "rest", mock_rest):
            self._driver.delete_share(self._context, share)
        mock_rest.folders.delete.assert_called_once_with(
            path="/fake/manila-fakeid"
        )
        mock_rest.views.delete.assert_called_once_with(name="fakeid")
        mock_rest.quotas.delete.assert_called_once_with(name="fakeid")
        mock_rest.view_policies.delete.assert_called_once_with(name="fakeid")

    def test_update_access_rules_wrong_proto(self):
        share = fake_share.fake_share(share_proto="SMB")
        access_rules = [
            {
                "access_level": "rw",
                "access_to": "127.0.0.1",
                "access_type": "ip"
            }
        ]
        res = self._driver.update_access(
            self._context,
            share,
            access_rules,
            None,
            None,
            None
        )
        self.assertIsNone(res)

    def test_update_access_add_rules_no_policy(self):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = None
        access_rules = [
            {
                "access_level": "rw",
                "access_to": "127.0.0.1",
                "access_type": "ip"
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            with self.assertRaises(exception.ManilaException) as exc:
                self._driver.update_access(
                    self._context, share, access_rules, None, None, None
                )
            self.assertIn("Policy not found", str(exc.exception))

    @ddt.data(
        (["*"], ["10.10.10.1", "10.10.10.2"]),
        (["10.10.10.1", "10.10.10.2"], []),
        (["*"], []),
    )
    @ddt.unpack
    def test_update_access_add_rules(self, rw, ro):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=rw, nfs_read_only=ro
        )
        access_rules = [
            {
                "access_level": "rw",
                "access_to": "127.0.0.1",
                "access_type": "ip"
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context,
                share,
                access_rules,
                None,
                None,
                None
            )

        expected_ro = set(ro)
        if rw == ["*"]:
            expected_rw = {"127.0.0.1"}
        else:
            expected_rw = set(["127.0.0.1"] + rw)
        kw = mock_rest.view_policies.update.call_args.kwargs
        self.assertEqual(kw["name"], "fakeid")
        self.assertSetEqual(set(kw["nfs_read_write"]), expected_rw)
        self.assertSetEqual(set(kw["nfs_read_only"]), expected_ro)
        self.assertEqual(kw["nfs_no_squash"], ["*"])
        self.assertEqual(kw["nfs_root_squash"], ["*"])
        self.assertFalse(failed_rules)

        # and the same for ro
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=rw, nfs_read_only=ro
        )
        access_rules = [
            {
                "access_level": "ro",
                "access_to": "127.0.0.1",
                "access_type": "ip"
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context,
                share,
                access_rules,
                None,
                None,
                None
            )

        expected_rw = set(rw)
        if ro == ["*"]:
            expected_ro = {"127.0.0.1"}
        else:
            expected_ro = set(["127.0.0.1"] + ro)
        kw = mock_rest.view_policies.update.call_args.kwargs
        self.assertEqual(kw["name"], "fakeid")
        self.assertSetEqual(set(kw["nfs_read_write"]), expected_rw)
        self.assertSetEqual(set(kw["nfs_read_only"]), expected_ro)
        self.assertEqual(kw["nfs_no_squash"], ["*"])
        self.assertEqual(kw["nfs_root_squash"], ["*"])
        self.assertFalse(failed_rules)

    @ddt.data(
        (["*"], ["10.10.10.1", "10.10.10.2"]),
        (["10.10.10.1", "10.10.10.2"], []),
        (["*"], []),
    )
    @ddt.unpack
    def test_update_access_delete_rules(self, rw, ro):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=rw, nfs_read_only=ro
        )
        delete_rules = [
            {
                "access_level": "rw",
                "access_to": "10.10.10.1",
                "access_type": "ip"
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context, share,
                None,
                None,
                delete_rules,
                None,
            )

        expected_ro = set(ro)
        if rw == ["*"]:
            expected_rw = set(rw)
        else:
            expected_rw = set([r for r in rw if r != "10.10.10.1"])
        kw = mock_rest.view_policies.update.call_args.kwargs
        self.assertEqual(kw["name"], "fakeid")
        self.assertSetEqual(set(kw["nfs_read_write"]), expected_rw)
        self.assertSetEqual(set(kw["nfs_read_only"]), expected_ro)
        self.assertEqual(kw["nfs_no_squash"], ["*"])
        self.assertEqual(kw["nfs_root_squash"], ["*"])
        self.assertFalse(failed_rules)

        # and the same for ro
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=rw, nfs_read_only=ro
        )
        delete_rules = [
            {
                "access_level": "ro",
                "access_to": "10.10.10.1",
                "access_type": "ip"
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context, share, None, None, delete_rules, None
            )

        expected_rw = set(rw)
        if ro == ["*"]:
            expected_ro = set(ro)
        else:
            expected_ro = set([r for r in ro if r != "10.10.10.1"])
        kw = mock_rest.view_policies.update.call_args.kwargs
        self.assertEqual(kw["name"], "fakeid")
        self.assertSetEqual(set(kw["nfs_read_write"]), expected_rw)
        self.assertSetEqual(set(kw["nfs_read_only"]), expected_ro)
        self.assertEqual(kw["nfs_no_squash"], ["*"])
        self.assertEqual(kw["nfs_root_squash"], ["*"])
        self.assertFalse(failed_rules)

    def test_update_access_for_cidr(self):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=["10.0.0.1"], nfs_read_only=["*"]
        )
        access_rules = [
            {
                "access_level": "ro",
                "access_to": "10.0.0.1/29",
                "access_type": "ip",
                "access_id": 12345,
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context,
                share,
                access_rules,
                None,
                None,
                None
            )
            kw = mock_rest.view_policies.update.call_args.kwargs
            self.assertEqual(kw["name"], "fakeid")
            self.assertSetEqual(set(kw["nfs_read_write"]), {"10.0.0.1"})
            self.assertSetEqual(
                set(kw["nfs_read_only"]),
                {
                    '10.0.0.1',
                    '10.0.0.3',
                    '10.0.0.2',
                    '10.0.0.6',
                    '10.0.0.5',
                    '10.0.0.4'
                }
            )
            self.assertFalse(failed_rules)

        delete_rules = [
            {
                "access_level": "ro",
                "access_to": "10.0.0.1/30",
                "access_type": "ip",
                "access_id": 12345,
            }
        ]
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=["10.0.0.1"],
            nfs_read_only=[
                '10.0.0.1',
                '10.0.0.3',
                '10.0.0.2',
                '10.0.0.6',
                '10.0.0.5',
                '10.0.0.4',
            ]
        )
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context,
                share,
                None,
                None,
                delete_rules,
                None
            )
            kw = mock_rest.view_policies.update.call_args.kwargs
            self.assertEqual(kw["name"], "fakeid")
            self.assertSetEqual(set(kw["nfs_read_write"]), {"10.0.0.1"})
            self.assertSetEqual(
                set(kw["nfs_read_only"]),
                {'10.0.0.6', '10.0.0.3', '10.0.0.4', '10.0.0.5'}
            )
            self.assertFalse(failed_rules)

    def test_update_access_for_invalid_rules(self):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.one.return_value = driver_util.Bunch(
            id=1, nfs_read_write=["10.0.0.1"], nfs_read_only=["*"]
        )
        access_rules = [
            {
                "access_level": "ry",
                "access_to": "10.0.0.1",
                "access_type": "ip",
                "access_id": 12345,
                "id": 12345,
            },
            {
                "access_level": "ro",
                "access_to": "10.0.0.2",
                "access_type": "ip",
                "access_id": 12346,
                "id": 12346,
            },
            {
                "access_level": "ro",
                "access_to": "10.0.0.2/33",
                "access_type": "ip",
                "access_id": 12347,
                "id": 12347,
            },
            {
                "access_level": "rw",
                "access_to": "10.0.0.2.4",
                "access_type": "ip",
                "access_id": 12348,
                "id": 12348,
            }
        ]
        with mock.patch.object(self._driver, "rest", mock_rest):
            failed_rules = self._driver.update_access(
                self._context,
                share,
                access_rules,
                None,
                None,
                None
            )
            kw = mock_rest.view_policies.update.call_args.kwargs
            self.assertEqual(kw["name"], "fakeid")
            self.assertSetEqual(set(kw["nfs_read_write"]), {"10.0.0.1"})
            self.assertSetEqual(set(kw["nfs_read_only"]), {'10.0.0.2'})
            self.assertDictEqual(
                failed_rules,
                {
                    12345: {'state': 'error'},
                    12347: {'state': 'error'},
                    12348: {'state': 'error'}
                }
            )

    def test_resize_share_quota_not_found(self):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.quotas.one.return_value = None
        with mock.patch.object(self._driver, "rest", mock_rest):
            with self.assertRaises(exception.ShareNotFound) as exc:
                self._driver.extend_share(share, 10000)
            self.assertIn("could not be found", str(exc.exception))

    def test_resize_share_ok(self):
        share = fake_share.fake_share(share_proto="NFS")
        mock_rest = self._create_mocked_rest_api()
        mock_rest.quotas.one.return_value = driver_util.Bunch(
            id=1, used_effective_capacity=1073741824
        )
        with mock.patch.object(self._driver, "rest", mock_rest):
            self._driver.extend_share(share, 50)
            mock_rest.quotas.update.assert_called_with(
                1, hard_limit=53687091200
            )
            mock_rest.quotas.update.reset()
            self._driver.shrink_share(share, 20)
            mock_rest.quotas.update.assert_called_with(
                1, hard_limit=21474836480
            )

    def test_resize_share_exceeded_hard_limit(self):
        share = fake_share.fake_share(
            share_proto="NFS"
        )
        mock_rest = self._create_mocked_rest_api()
        mock_rest.quotas.one.return_value = driver_util.Bunch(
            id=1, used_effective_capacity=10737418240
        )  # 10GB
        with mock.patch.object(self._driver, "rest", mock_rest):
            with self.assertRaises(exception.ShareShrinkingPossibleDataLoss):
                self._driver.shrink_share(share, 9.7)
            self._driver.shrink_share(share, 10)

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_snapshot(self, mock_get_extra_specs):
        mock_get_extra_specs.return_value = {}
        share = fake_share.fake_share(share_proto="NFS")
        snapshot = driver_util.Bunch(
            name="fakesnap", share_instance_id="fakeid", share=share
        )
        mock_rest = self._create_mocked_rest_api()
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            tenant_id=123
        )
        with mock.patch.object(self._driver, "rest", mock_rest):
            self._driver.create_snapshot(self._context, snapshot, None)
        mock_rest.snapshots.create.assert_called_once_with(
            path="/fake/manila-fakeid", name="fakesnap", tenant_id=123
        )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_snapshot_with_custom_vippool(self, mock_get_extra_specs):
        """Test snapshot creation with custom vippool from extra specs."""
        mock_get_extra_specs.return_value = {
            'vast:vippool_name': 'custom-vippool'
        }
        share = fake_share.fake_share(share_proto="NFS")
        snapshot = driver_util.Bunch(
            name="fakesnap", share_instance_id="fakeid", share=share
        )
        mock_rest = self._create_mocked_rest_api()
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            tenant_id=456
        )
        with mock.patch.object(self._driver, "rest", mock_rest):
            self._driver.create_snapshot(self._context, snapshot, None)

        # Verify that custom-vippool was used
        mock_rest.vip_pools.one.assert_called_once_with(
            name="custom-vippool",
            fail_if_missing=True,
        )
        mock_rest.snapshots.create.assert_called_once_with(
            path="/fake/manila-fakeid", name="fakesnap", tenant_id=456
        )

    def test_delete_snapshot(self):
        snapshot = driver_util.Bunch(
            name="fakesnap", share_instance_id="fakeid"
        )
        mock_rest = self._create_mocked_rest_api()
        with mock.patch.object(self._driver, "rest", mock_rest):
            self._driver.delete_snapshot(self._context, snapshot, None)
        mock_rest.snapshots.delete.assert_called_once_with(name="fakesnap")

    def test_network_allocation_number(self):
        self.assertEqual(self._driver.get_network_allocations_number(), 0)

    @ddt.data([], ['fake/path/1', 'fake/path'])
    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_ensure_shares(self, fake_export_locations, mock_get_extra_specs):
        mock_get_extra_specs.return_value = {}
        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.ensure.return_value = driver_util.Bunch(id=1)
        mock_rest.quotas.ensure.return_value = driver_util.Bunch(
            id=2, hard_limit=1073741824
        )
        mock_rest.views.ensure.return_value = driver_util.Bunch(
            id=3, policy="test_policy"
        )
        shares = [
            fake_share.fake_share(
                id=_id,
                share_id=share_id,
                share_proto="NFS",
                export_locations=fake_export_locations,
            )
            for _id, share_id in enumerate(["123", "456", "789"], 1)
        ]
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            ip_ranges=[["1.1.1.0", "1.1.1.1"]],
            tenant_id=123
        )
        with mock.patch.object(self._driver, "rest", mock_rest):
            locations = self._driver.ensure_shares(self._context, shares)

        common = {"is_admin_only": False}
        self.assertDictEqual(
            locations,
            {
                1: {
                    "export_locations": [
                        {"path": "1.1.1.0:/fake/manila-1", **common},
                        {"path": "1.1.1.1:/fake/manila-1", **common},
                    ]
                },
                2: {
                    "export_locations": [
                        {"path": "1.1.1.0:/fake/manila-2", **common},
                        {"path": "1.1.1.1:/fake/manila-2", **common},
                    ]
                },
                3: {
                    "export_locations": [
                        {"path": "1.1.1.0:/fake/manila-3", **common},
                        {"path": "1.1.1.1:/fake/manila-3", **common},
                    ]
                },
            },
        )

    def test_backend_info(self):
        backend_info = self._driver.get_backend_info(self._context)
        self.assertDictEqual(
            backend_info,
            {'vast_vippool_name': 'vippool', 'vast_mgmt_host': 'test'}
        )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_share_with_extra_specs_vippool(self, mock_get_specs):
        """Test that vippool_name from extra specs overrides config."""
        share = fake_share.fake_share(
            share_proto="NFS",
            share_type_id="fake-type-id",
        )
        mock_get_specs.return_value = {
            'vast:vippool_name': 'custom-vippool'
        }

        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.ensure.return_value = driver_util.Bunch(id=1)
        mock_rest.quotas.ensure.return_value = driver_util.Bunch(
            id=2, hard_limit=1073741824
        )
        mock_rest.views.ensure.return_value = driver_util.Bunch(
            id=3, policy="fakeid"
        )
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            ip_ranges=[["2.2.2.0", "2.2.2.1"]],
            tenant_id=456
        )

        with mock.patch.object(self._driver, "rest", mock_rest):
            location = self._driver.create_share(self._context, share)

            # Verify that custom-vippool was used instead of config's vippool
            mock_rest.vip_pools.one.assert_called_once_with(
                name="custom-vippool",
                fail_if_missing=True,
            )
            self.assertEqual(len(location), 2)
            self.assertEqual(
                location[0]['path'], '2.2.2.0:/fake/manila-fakeid'
            )
            self.assertEqual(
                location[1]['path'], '2.2.2.1:/fake/manila-fakeid'
            )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_share_without_extra_specs_uses_config(
            self, mock_get_specs
    ):
        """Test that config vippool_name is used when no extra specs."""
        share = fake_share.fake_share(
            share_proto="NFS",
            share_type_id="fake-type-id",
        )
        mock_get_specs.return_value = {}

        mock_rest = self._create_mocked_rest_api()
        mock_rest.view_policies.ensure.return_value = driver_util.Bunch(id=1)
        mock_rest.quotas.ensure.return_value = driver_util.Bunch(
            id=2, hard_limit=1073741824
        )
        mock_rest.views.ensure.return_value = driver_util.Bunch(
            id=3, policy="fakeid"
        )
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            ip_ranges=[["1.1.1.0", "1.1.1.1"]],
            tenant_id=123
        )

        with mock.patch.object(self._driver, "rest", mock_rest):
            self._driver.create_share(self._context, share)

            # Verify that config's vippool was used
            mock_rest.vip_pools.one.assert_called_once_with(
                name="vippool",
                fail_if_missing=True,
            )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_share_without_vippool_raises_error(self, mock_get_specs):
        """Test that error is raised when vippool_name is not available."""
        mock_get_specs.return_value = {}
        # Create driver without vippool_name in config
        self.fake_conf.set_default("vast_vippool_name", None)
        _driver = driver.VASTShareDriver(
            execute=mock.MagicMock(), configuration=self.fake_conf
        )
        _driver.do_setup(self._context)

        # Create share without vippool in config or extra specs
        share = fake_share.fake_share(
            share_proto="NFS",
        )

        with self.assertRaises(exception.VastDriverException) as exc:
            _driver._ensure_share(share)

        self.assertIn(
            "VIP pool name must be specified", str(exc.exception)
        )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_create_share_with_empty_vip_pool_raises_error(
            self,
            mock_get_specs,
    ):
        """Test that error is raised when vip pool has no available IPs."""
        mock_get_specs.return_value = {}
        share = fake_share.fake_share(share_proto="NFS")

        mock_rest = self._create_mocked_rest_api()
        # Mock vip_pools.one() to return pool with empty ip_ranges
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            name="vippool",
            ip_ranges=[],  # No IP ranges
            tenant_id=123
        )

        with mock.patch.object(self._driver, "rest", mock_rest):
            with self.assertRaises(exception.VastDriverException) as exc:
                self._driver.create_share(self._context, share)

            self.assertIn("has no available vips", str(exc.exception))

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_get_vip_pool_for_share_from_extra_specs(self, mock_get_specs):
        """Test _get_vip_pool_for_share using extra specs."""
        mock_get_specs.return_value = {'vast:vippool_name': 'custom-pool'}
        share = fake_share.fake_share(share_proto="NFS")

        mock_rest = self._create_mocked_rest_api()
        mock_vippool = driver_util.Bunch(
            name="custom-pool",
            ip_ranges=[["1.1.1.1", "1.1.1.2"]],
            tenant_id=456
        )
        mock_rest.vip_pools.one.return_value = mock_vippool

        with mock.patch.object(self._driver, "rest", mock_rest):
            result = self._driver._get_vip_pool_for_share(share)

        self.assertEqual(result, mock_vippool)
        mock_rest.vip_pools.one.assert_called_once_with(
            name="custom-pool",
            fail_if_missing=True,
        )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_get_vip_pool_for_share_from_config(self, mock_get_specs):
        """Test _get_vip_pool_for_share using config default."""
        mock_get_specs.return_value = {}
        share = fake_share.fake_share(share_proto="NFS")

        mock_rest = self._create_mocked_rest_api()
        mock_vippool = driver_util.Bunch(
            name="vippool",
            ip_ranges=[["2.2.2.1", "2.2.2.2"]],
            tenant_id=789
        )
        mock_rest.vip_pools.one.return_value = mock_vippool

        with mock.patch.object(self._driver, "rest", mock_rest):
            result = self._driver._get_vip_pool_for_share(share)

        self.assertEqual(result, mock_vippool)
        mock_rest.vip_pools.one.assert_called_once_with(
            name="vippool",
            fail_if_missing=True,
        )

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_get_tenant_id_for_share(self, mock_get_specs):
        """Test _get_tenant_id_for_share returns correct tenant_id."""
        mock_get_specs.return_value = {}
        share = fake_share.fake_share(share_proto="NFS")

        mock_rest = self._create_mocked_rest_api()
        mock_rest.vip_pools.one.return_value = driver_util.Bunch(
            name="vippool",
            tenant_id=999
        )

        with mock.patch.object(self._driver, "rest", mock_rest):
            tenant_id = self._driver._get_tenant_id_for_share(share)

        self.assertEqual(tenant_id, 999)


class TestExtraSpecsParsing(unittest.TestCase):
    """Test extra specs parsing functions."""

    def test_get_opts_from_specs_with_vast_namespace(self):
        """Test parsing extra specs with vast: namespace."""
        specs = {
            'vast:vippool_name': 'pool-1',
            'capabilities:dedupe': 'true',
            'other:setting': 'value',
        }
        opts = driver_util.get_opts_from_specs(specs)
        self.assertEqual(opts['vippool_name'], 'pool-1')

    def test_get_opts_from_specs_case_insensitive(self):
        """Test that namespace and key are case insensitive."""
        specs = {
            'VAST:VipPool_Name': 'pool-1',
            'Vast:VIPPOOL_NAME': 'pool-2',  # Should be ignored, first one wins
        }
        opts = driver_util.get_opts_from_specs(specs)
        # First matching key should be used
        self.assertIn(opts['vippool_name'], ['pool-1', 'pool-2'])

    def test_get_opts_from_specs_without_namespace(self):
        """Test that options without namespace are ignored."""
        specs = {
            'vippool_name': 'pool-1',
            'other_setting': 'value',
        }
        opts = driver_util.get_opts_from_specs(specs)
        self.assertIsNone(opts['vippool_name'])

    def test_get_opts_from_specs_with_invalid_format(self):
        """Test that invalid format keys are skipped."""
        specs = {
            'vast:vippool_name:extra': 'pool-1',  # Too many colons
            'vast:vippool_name': 'pool-2',
        }
        opts = driver_util.get_opts_from_specs(specs)
        self.assertEqual(opts['vippool_name'], 'pool-2')

    def test_get_opts_from_specs_empty(self):
        """Test parsing empty specs returns defaults."""
        specs = {}
        opts = driver_util.get_opts_from_specs(specs)
        self.assertIsNone(opts['vippool_name'])

    def test_get_opts_from_specs_with_empty_scope(self):
        """Test that keys with empty scope are handled correctly."""
        specs = {
            ':vippool_name': 'pool-1',  # Empty scope
            'vast:vippool_name': 'pool-2',
        }
        opts = driver_util.get_opts_from_specs(specs)
        # Empty scope should be skipped, so pool-2 should be used
        self.assertEqual(opts['vippool_name'], 'pool-2')

    def test_get_opts_from_specs_with_empty_option_key(self):
        """Test that keys with empty option_key are handled correctly."""
        specs = {
            'vast:': 'some-value',  # Empty option_key
            'vast:vippool_name': 'pool-1',
        }
        opts = driver_util.get_opts_from_specs(specs)
        # Empty option_key should be skipped, so pool-1 should be used
        self.assertEqual(opts['vippool_name'], 'pool-1')

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_get_share_extra_specs_params(self, mock_get_specs):
        """Test get_share_extra_specs_params function."""
        mock_get_specs.return_value = {
            'vast:vippool_name': 'pool-1',
        }

        share = {'share_type_id': 'fake-type-id'}
        opts = driver_util.get_share_extra_specs_params(share)

        self.assertEqual(opts['vippool_name'], 'pool-1')
        mock_get_specs.assert_called_once_with(share)

    @mock.patch('manila.share.share_types.get_extra_specs_from_share')
    def test_get_share_extra_specs_params_no_extra_specs(self, mock_get_specs):
        """Test get_share_extra_specs_params with no extra specs."""
        mock_get_specs.return_value = {}

        share = {'share_type_id': 'fake-type-id'}
        opts = driver_util.get_share_extra_specs_params(share)

        # Should return default VAST extra specs when no vast: specs provided
        self.assertEqual(opts, {'vippool_name': None})
        mock_get_specs.assert_called_once_with(share)


class TestPolicyPayloadFromRules(unittest.TestCase):
    def test_policy_payload_from_rules_update(self):
        rules = [{"access_level": "rw", "access_to": "127.0.0.1"}]
        policy = mock.MagicMock()
        policy.nfs_read_write = ["127.0.0.1"]
        policy.nfs_read_only = []
        result = driver.policy_payload_from_rules(rules, policy, "update")
        self.assertEqual(
            result, {"nfs_read_write": ["127.0.0.1"], "nfs_read_only": []}
        )

    def test_policy_payload_from_rules_deny(self):
        rules = [{"access_level": "rw", "access_to": "127.0.0.1"}]
        policy = mock.MagicMock()
        policy.nfs_read_write = ["127.0.0.1"]
        policy.nfs_read_only = []
        result = driver.policy_payload_from_rules(rules, policy, "deny")
        self.assertEqual(result, {"nfs_read_write": [], "nfs_read_only": []})

    def test_policy_payload_from_rules_invalid_action(self):
        rules = [{"access_level": "rw", "access_to": "127.0.0.1"}]
        with self.assertRaises(ValueError):
            driver.policy_payload_from_rules(rules, None, "invalid")

    def test_policy_payload_from_rules_invalid_ip(self):
        rules = [{"access_level": "rw", "access_to": "1.0.0.257"}]
        with self.assertRaises(netaddr.core.AddrFormatError):
            driver.policy_payload_from_rules(rules, None, "deny")


class TestValidateAccessRules(unittest.TestCase):
    def test_validate_access_rules_invalid_type(self):
        rule = {"access_type": "INVALID", "access_level": "rw"}
        with self.assertRaises(exception.InvalidShareAccess):
            driver.validate_access_rule(rule)

    def test_validate_access_rules_invalid_level(self):
        rule = {"access_type": "ip", "access_level": "INVALID"}
        with self.assertRaises(exception.InvalidShareAccessLevel):
            driver.validate_access_rule(rule)
