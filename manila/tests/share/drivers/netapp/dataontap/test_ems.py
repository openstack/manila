# Copyright (c) 2026 NetApp, Inc.
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
"""Unit tests for the NetApp Manila EMS periodic reporter module."""

import copy
import json
import re
import socket
from unittest import mock

from manila.share.drivers.netapp.dataontap import ems as netapp_ems
from manila import test
from manila.tests.share.drivers.netapp.dataontap import fakes as fake


class EmsReporterTestCase(test.TestCase):
    """Tests for :mod:`manila.share.drivers.netapp.dataontap.ems`."""

    def setUp(self):
        super().setUp()

        self.library = mock.Mock()
        self.library.driver_name = fake.DRIVER_NAME
        self.library._app_version = fake.APP_VERSION
        self.library._backend_name = fake.BACKEND_NAME
        self.library._flexgroup_pools = {}
        self.library._have_cluster_creds = False
        self.library._cluster_info = {}
        self.library.get_configured_ip_versions.return_value = [4]
        self.library.configuration.safe_get.return_value = None
        self.library.configuration.driver_handles_share_servers = True
        # Mock auto-creates VERSION as a child Mock which is not
        # JSON-serializable; remove it so getattr uses _EMS_PAYLOAD_VERSION.
        del self.library.VERSION

    def test_build_ems_log_message_0_structure(self):
        """event-0 message has all required EMS envelope fields."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)

        self.assertEqual('0', result['event-id'])
        self.assertEqual(fake.HOST_NAME, result['computer-name'])
        self.assertEqual('Manila driver %s' % fake.DRIVER_NAME,
                         result['event-source'])
        self.assertEqual(fake.APP_VERSION, result['app-version'])
        self.assertEqual('provisioning', result['category'])
        self.assertEqual('5', result['log-level'])
        self.assertEqual('false', result['auto-support'])

    def test_build_ems_log_message_0_payload_schema(self):
        """event-0 event-description is valid JSON with expected keys."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        payload = json.loads(result['event-description'])

        self.assertIn('openstack', payload)
        self.assertIn('driver_name', payload)
        self.assertIn('driver_version', payload)
        self.assertIn('backend_name', payload)
        self.assertIn('features', payload)
        self.assertIn('configs', payload)
        self.assertNotIn('object_counts', payload)

    def test_build_ems_log_message_0_features(self):
        """event-0 payload includes all expected feature flag keys."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        expected_feature_keys = (
            'driver_handles_share_servers',
            'storage_protocol',
            'flexgroup_pools_configured',
            'netapp_enable_flexgroup',
            'flexgroup_pool_only',
            'consistent_snapshot_support',
            'ipv4_support',
            'ipv6_support',
            'netapp_enabled_share_protocols',
            'thin_provisioning',
            'dedupe',
            'compression',
            'qos_support',
            'qos_type_support',
            'netapp_flexvol_encryption',
            'netapp_use_legacy_client',
            'encryption_support',
            'netapp_aggregate_encryption_support',
            'netapp_transport_type',
            'netapp_certificate_auth',
            'netapp_certificate_host_validation',
            'netapp_cifs_aes_encryption',
            'netapp_cifs_smb_signing',
            'netapp_enable_logical_space_reporting',
            'netapp_restrict_lif_creation_per_ha_pair',
            'backup_configured',
            'replication_domain',
            'replication_type',
            'netapp_snapmirror_schedule',
        )
        for key in expected_feature_keys:
            self.assertIn(key, features)

    def test_build_ems_log_message_0_ipv6_reported(self):
        """ipv6_support is True when the backend has an IPv6 LIF."""
        self.library.get_configured_ip_versions.return_value = [4, 6]
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['ipv4_support'])
        self.assertTrue(features['ipv6_support'])

    def test_build_ems_log_message_0_cluster_creds_features(self):
        """qos_support and qos_type_support reflect cluster credentials."""
        self.library._have_cluster_creds = True
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['qos_support'])
        self.assertTrue(features['qos_type_support'])

    def test_build_ems_log_message_0_replication_type_set(self):
        """replication_type list is included when replication_domain is set."""
        self.library.configuration.safe_get.side_effect = (
            lambda key: 'test_domain' if key == 'replication_domain' else None
        )
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual('test_domain', features['replication_domain'])
        self.assertIn('dr', features['replication_type'])
        self.assertIn('readable', features['replication_type'])

    def test_build_ems_log_message_0_ip_version_failure_defaults_ipv4(self):
        """IP version lookup failure defaults to IPv4=True, IPv6=False."""
        self.library.get_configured_ip_versions.side_effect = Exception(
            'no client')
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['ipv4_support'])
        self.assertFalse(features['ipv6_support'])

    def test_build_ems_log_message_0_dhss_true(self):
        """DHSS setting is reported as a boolean in features."""
        self.library.configuration.driver_handles_share_servers = True
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['driver_handles_share_servers'])

    def test_build_ems_log_message_0_dhss_false(self):
        """DHSS setting is reported as a boolean in features."""
        self.library.configuration.driver_handles_share_servers = False
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertFalse(features['driver_handles_share_servers'])

    def test_build_ems_log_message_0_storage_protocol_from_conf(self):
        """storage_protocol is derived from CONF.enabled_share_protocols."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))
        self.override_config('enabled_share_protocols', ['NFS'])

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual('NFS', features['storage_protocol'])

    def test_build_ems_log_message_0_storage_protocol_nfs_cifs(self):
        """storage_protocol is NFS_CIFS when both protocols are enabled."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))
        self.override_config('enabled_share_protocols', ['NFS', 'CIFS'])

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual('NFS_CIFS', features['storage_protocol'])

    def test_build_ems_log_message_0_provisioning_capabilities(self):
        """thin_provisioning, dedupe, compression each report [True, False]."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual([True, False], features['thin_provisioning'])
        self.assertEqual([True, False], features['dedupe'])
        self.assertEqual([True, False], features['compression'])

    def test_build_ems_log_message_0_https_transport(self):
        """netapp_transport_type is reported from config."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: 'https' if k == 'netapp_transport_type' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual('https', features['netapp_transport_type'])

    def test_build_ems_log_message_0_http_transport_default(self):
        """netapp_transport_type defaults to http when not configured."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual('http', features['netapp_transport_type'])

    def test_build_ems_log_message_0_certificate_auth_configured(self):
        """netapp_certificate_auth is True when certificate file is set."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: '/path/to/cert.pem'
            if k == 'netapp_certificate_file' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['netapp_certificate_auth'])

    def test_build_ems_log_message_0_certificate_auth_not_configured(self):
        """netapp_certificate_auth is False when no certificate file set."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertFalse(features['netapp_certificate_auth'])

    def test_build_ems_log_message_0_cifs_security_flags(self):
        """CIFS AES encryption and SMB signing are reported from config."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: True if k in (
                'netapp_cifs_aes_encryption',
                'netapp_cifs_smb_signing') else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['netapp_cifs_aes_encryption'])
        self.assertTrue(features['netapp_cifs_smb_signing'])

    def test_build_ems_log_message_0_backup_configured(self):
        """backup_configured is True when backup types are set."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: ['eng_backup']
            if k == 'netapp_enabled_backup_types' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['backup_configured'])

    def test_build_ems_log_message_0_snapmirror_schedule_with_replication(
            self):
        """snapmirror_schedule is reported when replication_domain is set."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: 'test_domain' if k == 'replication_domain'
            else 'hourly' if k == 'netapp_snapmirror_schedule'
            else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual('hourly', features['netapp_snapmirror_schedule'])

    def test_build_ems_log_message_0_snapmirror_schedule_without_replication(
            self):
        """netapp_snapmirror_schedule is None when no replication_domain."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertIsNone(features['netapp_snapmirror_schedule'])

    def test_build_ems_log_message_0_certificate_host_validation_enabled(
            self):
        """netapp_certificate_host_validation is True when enabled."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: True
            if k == 'netapp_certificate_host_validation' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['netapp_certificate_host_validation'])

    def test_build_ems_log_message_0_certificate_host_validation_disabled(
            self):
        """netapp_certificate_host_validation defaults to False."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertFalse(features['netapp_certificate_host_validation'])

    def test_build_ems_log_message_0_flexgroup_enabled(self):
        """netapp_enable_flexgroup is True when set in config."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: True if k == 'netapp_enable_flexgroup' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['netapp_enable_flexgroup'])

    def test_build_ems_log_message_0_flexgroup_disabled(self):
        """netapp_enable_flexgroup defaults to False."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertFalse(features['netapp_enable_flexgroup'])

    def test_build_ems_log_message_0_netapp_enabled_share_protocols(self):
        """netapp_enabled_share_protocols reports NFS versions from config."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: ['nfs3', 'nfs4.0', 'nfs4.1']
            if k == 'netapp_enabled_share_protocols' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertEqual(['nfs3', 'nfs4.0', 'nfs4.1'],
                         features['netapp_enabled_share_protocols'])

    def test_build_ems_log_message_0_logical_space_reporting_enabled(self):
        """netapp_enable_logical_space_reporting is True when configured."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: True
            if k == 'netapp_enable_logical_space_reporting' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(features['netapp_enable_logical_space_reporting'])

    def test_build_ems_log_message_0_logical_space_reporting_disabled(self):
        """netapp_enable_logical_space_reporting defaults to False."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertFalse(features['netapp_enable_logical_space_reporting'])

    def test_build_ems_log_message_0_restrict_lif_ha_pair_enabled(self):
        """netapp_restrict_lif_creation_per_ha_pair is True when set."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: True
            if k == 'netapp_restrict_lif_creation_per_ha_pair' else None)
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertTrue(
            features['netapp_restrict_lif_creation_per_ha_pair'])

    def test_build_ems_log_message_0_restrict_lif_ha_pair_disabled(self):
        """netapp_restrict_lif_creation_per_ha_pair defaults to False."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        features = json.loads(result['event-description'])['features']

        self.assertFalse(
            features['netapp_restrict_lif_creation_per_ha_pair'])

    def test_build_ems_log_message_0_openstack_is_app_version(self):
        """openstack field equals the library app version string."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems.build_ems_log_message_0(self.library)
        payload = json.loads(result['event-description'])

        self.assertEqual(fake.APP_VERSION, payload['openstack'])

    # ------------------------------------------------------------------
    # _safe_hostname
    # ------------------------------------------------------------------

    def test_safe_hostname_returns_dns_name(self):
        """A non-IP hostname is returned as-is."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value='manila-node.example.com'))

        self.assertEqual('manila-node.example.com',
                         netapp_ems._safe_hostname())

    def test_safe_hostname_ipv4_falls_back_to_fqdn(self):
        """When gethostname returns an IPv4, getfqdn DNS name is used."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value='192.168.1.10'))
        self.mock_object(socket, 'getfqdn',
                         mock.Mock(return_value='manila-node.example.com'))

        self.assertEqual('manila-node.example.com',
                         netapp_ems._safe_hostname())

    def test_safe_hostname_both_ip_returns_placeholder(self):
        """When both gethostname and getfqdn return IPs, placeholder used."""
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value='10.0.0.1'))
        self.mock_object(socket, 'getfqdn',
                         mock.Mock(return_value='10.0.0.1'))

        self.assertEqual('Manila_node', netapp_ems._safe_hostname())

    # ------------------------------------------------------------------
    # build_ems_log_message_1
    # ------------------------------------------------------------------

    def test_build_ems_log_message_1_structure(self):
        """event-1 message has all required EMS envelope fields."""
        pool_info = copy.deepcopy(fake.EMS_POOL_INFO)
        self.library._get_pools.return_value = []

        result = netapp_ems.build_ems_log_message_1(self.library, pool_info)

        self.assertEqual('1', result['event-id'])
        self.assertIn('pools', json.loads(result['event-description']))

    def test_build_ems_log_message_1_adds_pool_stats(self):
        """pool_stats list is added to the pools dict."""
        pool_info = copy.deepcopy(fake.EMS_POOL_INFO)
        fake_pools = [
            {
                'pool_name': 'pool1',
                'total_capacity_gb': 400,
                'free_capacity_gb': 200,
                'utilization': 50.0,
                'extra_key': 'should_not_appear',
            },
        ]
        self.library._get_pools.return_value = fake_pools

        result = netapp_ems.build_ems_log_message_1(self.library, pool_info)
        pools = json.loads(result['event-description'])['pools']

        self.assertIn('pool_stats', pools)
        self.assertEqual(1, len(pools['pool_stats']))
        stat = pools['pool_stats'][0]
        self.assertEqual('pool1', stat['pool_name'])
        self.assertEqual(400, stat['total_capacity_gb'])
        self.assertNotIn('extra_key', stat)

    def test_build_ems_log_message_1_preserves_existing_keys(self):
        """vserver, aggregates, flexgroup_aggregates are preserved."""
        pool_info = copy.deepcopy(fake.EMS_POOL_INFO)
        self.library._get_pools.return_value = []

        result = netapp_ems.build_ems_log_message_1(self.library, pool_info)
        pools = json.loads(result['event-description'])['pools']

        self.assertEqual(fake.VSERVER1, pools['vserver'])
        self.assertIn('aggregates', pools)
        self.assertIn('flexgroup_aggregates', pools)

    def test_build_ems_log_message_1_get_pools_failure_is_tolerated(self):
        """A _get_pools failure leaves pool_stats absent, not an error."""
        pool_info = copy.deepcopy(fake.EMS_POOL_INFO)
        self.library._get_pools.side_effect = Exception('SSC not ready')

        result = netapp_ems.build_ems_log_message_1(self.library, pool_info)
        pools = json.loads(result['event-description'])['pools']

        self.assertNotIn('pool_stats', pools)

    # ------------------------------------------------------------------
    # _build_base
    # ------------------------------------------------------------------

    def test_build_base_fields(self):
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = netapp_ems._build_base(self.library)

        self.assertEqual(fake.HOST_NAME, result['computer-name'])
        self.assertEqual('Manila driver %s' % fake.DRIVER_NAME,
                         result['event-source'])
        self.assertEqual(fake.APP_VERSION, result['app-version'])
        self.assertEqual('provisioning', result['category'])
        self.assertEqual('5', result['log-level'])
        self.assertEqual('false', result['auto-support'])


class NaeSupportTestCase(test.TestCase):
    """Tests for the nae_support logic in build_ems_log_message_0."""

    def setUp(self):
        super().setUp()
        self.library = mock.Mock()
        self.library.driver_name = fake.DRIVER_NAME
        self.library._app_version = fake.APP_VERSION
        self.library._backend_name = fake.BACKEND_NAME
        self.library._flexgroup_pools = {}
        self.library._have_cluster_creds = False
        self.library._cluster_info = {}
        self.library.get_configured_ip_versions.return_value = [4]
        self.library.configuration.driver_handles_share_servers = True
        del self.library.VERSION
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

    def _get_nae(self, legacy_client_val, nae_support_val):
        """Helper: configure and call build_ems_log_message_0, return nae."""
        self.library.configuration.safe_get.side_effect = (
            lambda k: legacy_client_val
            if k == 'netapp_use_legacy_client' else None)
        self.library._client.features.NAE_SUPPORT = nae_support_val
        result = netapp_ems.build_ems_log_message_0(self.library)
        return json.loads(result['event-description'])[
            'features']['netapp_aggregate_encryption_support']

    def test_nae_rest_client_ontap_supports_nae(self):
        """nae_support is True when REST client and ONTAP reports NAE."""
        self.assertTrue(self._get_nae(False, True))

    def test_nae_rest_client_ontap_no_nae(self):
        """nae_support is False when REST client but ONTAP has no NAE."""
        self.assertFalse(self._get_nae(False, False))

    def test_nae_zapi_client_always_false(self):
        """nae_support is False when legacy (ZAPI) client is used."""
        self.assertFalse(self._get_nae(True, True))

    def test_nae_exception_defaults_false(self):
        """nae_support defaults to False when feature lookup raises."""
        self.library.configuration.safe_get.return_value = None
        del self.library._client  # force AttributeError in the try block
        result = netapp_ems.build_ems_log_message_0(self.library)
        nae = json.loads(result['event-description'])[
            'features']['netapp_aggregate_encryption_support']
        self.assertFalse(nae)


class DriverVersionTestCase(test.TestCase):
    """Tests for driver_version in build_ems_log_message_0."""

    def setUp(self):
        super().setUp()
        self.library = mock.Mock()
        self.library.driver_name = fake.DRIVER_NAME
        self.library._app_version = fake.APP_VERSION
        self.library._backend_name = fake.BACKEND_NAME
        self.library._flexgroup_pools = {}
        self.library._have_cluster_creds = False
        self.library._cluster_info = {}
        self.library.get_configured_ip_versions.return_value = [4]
        self.library.configuration.safe_get.return_value = None
        self.library.configuration.driver_handles_share_servers = True
        del self.library.VERSION
        self.mock_object(socket, 'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

    def test_driver_version_is_string(self):
        """driver_version is a non-empty string from the Manila package."""
        result = netapp_ems.build_ems_log_message_0(self.library)
        payload = json.loads(result['event-description'])
        self.assertIsInstance(payload['driver_version'], str)
        self.assertGreater(len(payload['driver_version']), 0)


class IsExcludedConfigOptTestCase(test.TestCase):
    """Tests for :func:`netapp_ems._is_excluded_config_opt`."""

    def _make_opt(self, name, secret=False):
        opt = mock.Mock()
        opt.name = name
        opt.secret = secret
        return opt

    def test_excluded_when_name_in_EMS_SECRET_OPTS(self):
        """An option whose name is in EMS_SECRET_OPTS is excluded."""
        opt = self._make_opt('netapp_password', secret=False)
        self.assertTrue(netapp_ems._is_excluded_config_opt(opt))

    def test_excluded_when_opt_marked_secret(self):
        """An option with secret=True is excluded regardless of name."""
        opt = self._make_opt('some_new_credential', secret=True)
        self.assertTrue(netapp_ems._is_excluded_config_opt(opt))

    def test_not_excluded_for_normal_opt(self):
        """A regular, non-secret option is not excluded."""
        opt = self._make_opt('netapp_transport_type', secret=False)
        self.assertFalse(netapp_ems._is_excluded_config_opt(opt))

    def test_not_excluded_when_secret_attr_absent(self):
        """An option without a secret attribute at all is not excluded."""
        opt = mock.Mock(spec=['name'])  # no 'secret' attribute
        opt.name = 'netapp_enable_flexgroup'
        self.assertFalse(netapp_ems._is_excluded_config_opt(opt))


class SanitizeConfigsTestCase(test.TestCase):
    """Tests for :func:`netapp_ems._sanitize_configs`."""

    def test_strips_EMS_SECRET_OPTS_keys(self):
        """EMS_SECRET_OPTS keys are removed from the dict."""
        configs = {
            'netapp_password': 'secret',
            'netapp_transport_type': 'https',
            'netapp_login': 'admin',
        }
        result = netapp_ems._sanitize_configs(configs)
        self.assertNotIn('netapp_password', result)
        self.assertNotIn('netapp_login', result)
        self.assertIn('netapp_transport_type', result)

    def test_empty_dict_returns_empty(self):
        """An empty dict stays empty."""
        self.assertEqual({}, netapp_ems._sanitize_configs({}))

    def test_no_secret_keys_returns_unchanged(self):
        """A dict with no secret keys is returned unchanged."""
        configs = {'netapp_transport_type': 'http', 'netapp_enable_flexgroup':
                   True}
        self.assertEqual(configs, netapp_ems._sanitize_configs(configs))


class IsEmptyTestCase(test.TestCase):
    """Tests for :func:`netapp_ems._is_empty`."""

    def test_none_is_empty(self):
        self.assertTrue(netapp_ems._is_empty(None))

    def test_empty_string_is_empty(self):
        self.assertTrue(netapp_ems._is_empty(''))

    def test_empty_list_is_empty(self):
        self.assertTrue(netapp_ems._is_empty([]))

    def test_empty_dict_is_empty(self):
        self.assertTrue(netapp_ems._is_empty({}))

    def test_nonempty_values_are_not_empty(self):
        for val in (0, False, 'x', ['a'], {'k': 'v'}, 1):
            self.assertFalse(netapp_ems._is_empty(val))


class SafeConfigSnapshotTestCase(test.TestCase):
    """Tests for :func:`netapp_ems._safe_config_snapshot`."""

    def _make_config(self, values):
        config = mock.Mock()
        config.safe_get.side_effect = lambda k: values.get(k)
        return config

    def test_excludes_EMS_SECRET_OPTS_names(self):
        """Secret option names never appear in the snapshot."""
        values = {
            'netapp_password': 'topsecret',
            'netapp_login': 'admin',
            'netapp_transport_type': 'https',
        }
        config = self._make_config(values)
        result = netapp_ems._safe_config_snapshot(config)
        self.assertNotIn('netapp_password', result)
        self.assertNotIn('netapp_login', result)

    def test_excludes_secret_true_opts(self):
        """Options with secret=True on the opt object are excluded."""
        secret_opt = mock.Mock()
        secret_opt.name = 'future_credential'
        secret_opt.secret = True

        config = self._make_config({'future_credential': 'val'})

        with mock.patch.object(
                netapp_ems, '_NETAPP_OPT_GROUPS', [[secret_opt]]):
            result = netapp_ems._safe_config_snapshot(config)

        self.assertNotIn('future_credential', result)

    def test_includes_non_secret_opts_with_values(self):
        """Non-secret options with non-None values appear in the snapshot."""
        opt = mock.Mock()
        opt.name = 'netapp_transport_type'
        opt.secret = False

        config = self._make_config({'netapp_transport_type': 'https'})

        with mock.patch.object(
                netapp_ems, '_NETAPP_OPT_GROUPS', [[opt]]):
            result = netapp_ems._safe_config_snapshot(config)

        self.assertEqual({'netapp_transport_type': 'https'}, result)

    def test_omits_none_and_empty_values(self):
        """Options with None, empty string, or empty list are omitted."""
        opt1 = mock.Mock()
        opt1.name = 'opt_none'
        opt1.secret = False
        opt2 = mock.Mock()
        opt2.name = 'opt_empty_str'
        opt2.secret = False
        opt3 = mock.Mock()
        opt3.name = 'opt_with_value'
        opt3.secret = False

        config = self._make_config({
            'opt_none': None,
            'opt_empty_str': '',
            'opt_with_value': 'http',
        })

        with mock.patch.object(
                netapp_ems, '_NETAPP_OPT_GROUPS',
                [[opt1, opt2, opt3]]):
            result = netapp_ems._safe_config_snapshot(config)

        self.assertNotIn('opt_none', result)
        self.assertNotIn('opt_empty_str', result)
        self.assertIn('opt_with_value', result)

    def test_safe_get_exception_is_tolerated(self):
        """A config.safe_get failure for one key does not abort the rest."""
        opt1 = mock.Mock()
        opt1.name = 'bad_opt'
        opt1.secret = False
        opt2 = mock.Mock()
        opt2.name = 'good_opt'
        opt2.secret = False

        config = mock.Mock()
        config.safe_get.side_effect = (
            lambda k: (_ for _ in ()).throw(Exception('fail'))
            if k == 'bad_opt' else 'ok')

        with mock.patch.object(
                netapp_ems, '_NETAPP_OPT_GROUPS', [[opt1, opt2]]):
            result = netapp_ems._safe_config_snapshot(config)

        self.assertNotIn('bad_opt', result)
        self.assertEqual('ok', result.get('good_opt'))


class RegistryDrivenSensitivityTestCase(test.TestCase):
    """Registry-driven tests for EMS config-snapshot sensitivity filtering.

    These tests iterate the *live* ``_NETAPP_OPT_GROUPS`` registry so that
    future option additions are automatically covered without any test change.
    """

    # Sensitivity heuristic: option names matching this pattern should never
    # appear in a payload sent to ONTAP or written to operator logs.
    _SENSITIVE_PATTERN = re.compile(
        r'password|secret|token|key|cert|login|credential|private',
        re.IGNORECASE,
    )

    # Options that match the heuristic by name but are intentionally included
    # because they carry non-sensitive data (boolean flags or integer TTLs,
    # not actual credentials or key material):
    #   netapp_server_hostname           – ONTAP controller address.
    #   netapp_certificate_host_validation – boolean flag, not a credential.
    #   netapp_security_cert_expire_days   – integer TTL, not a credential.
    #   netapp_ssl_cert_verify             – boolean flag, not a credential.
    _KNOWN_SAFE_EXCEPTIONS = frozenset({
        'netapp_server_hostname',
        'netapp_certificate_host_validation',
        'netapp_security_cert_expire_days',
        'netapp_ssl_cert_verify',
    })

    def _make_config_with_all_opts(self):
        """Config mock returning a non-empty string for every opt."""
        config = mock.Mock()
        config.safe_get.side_effect = lambda k: 'test_value'
        return config

    def test_no_sensitive_name_in_snapshot(self):
        """No option matching the sensitivity heuristic appears in snapshot."""
        config = self._make_config_with_all_opts()
        result = netapp_ems._safe_config_snapshot(config)

        for key in result:
            if key in self._KNOWN_SAFE_EXCEPTIONS:
                continue
            self.assertIsNone(
                self._SENSITIVE_PATTERN.search(key),
                'Sensitive option %r leaked into EMS config snapshot. '
                'Add it to EMS_SECRET_OPTS or mark secret=True.' % key,
            )

    def test_all_secret_true_opts_excluded(self):
        """Every oslo.config option with secret=True is excluded."""
        config = self._make_config_with_all_opts()
        result = netapp_ems._safe_config_snapshot(config)

        for group in netapp_ems._NETAPP_OPT_GROUPS:
            for opt in group:
                if getattr(opt, 'secret', False):
                    self.assertNotIn(
                        opt.name, result,
                        'secret=True option %r leaked into EMS '
                        'config snapshot.' % opt.name,
                    )

    def test_EMS_SECRET_OPTS_all_excluded(self):
        """Every name in EMS_SECRET_OPTS is absent from the snapshot."""
        config = self._make_config_with_all_opts()
        result = netapp_ems._safe_config_snapshot(config)

        for name in netapp_ems.EMS_SECRET_OPTS:
            self.assertNotIn(
                name, result,
                'EMS_SECRET_OPTS entry %r leaked into snapshot.' % name,
            )
