# Copyright (c) 2014 NetApp, Inc.
# All Rights Reserved.
#
#     Licensed under the Apache License, Version 2.0 (the "License"); you may
#     not use this file except in compliance with the License. You may obtain
#     a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#     License for the specific language governing permissions and limitations
#     under the License.

import copy
import hashlib

import mock

from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.netapp import api as naapi
from manila.share.drivers.netapp import cluster_mode as driver
from manila import test
from manila import utils


class NetAppClusteredDrvTestCase(test.TestCase):
    """Test suite for NetApp Cluster Mode driver."""

    def setUp(self):
        super(NetAppClusteredDrvTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.driver = driver.NetAppClusteredShareDriver(
            self._db, configuration=configuration.Configuration(None))
        self.driver._client = mock.Mock()
        self.driver._client.send_request = mock.Mock()
        self._vserver_client = mock.Mock()
        self._vserver_client.send_request = mock.Mock()
        driver.NetAppApiClient = mock.Mock(return_value=self._vserver_client)
        self.share = {'id': 'fake_uuid',
                      'project_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'share_proto': 'fake',
                      'share_network_id': 'fake_net_id',
                      'share_server_id': 'fake-share-srv-id',
                      'network_info': {
                          'network_allocations': [
                              {'ip_address': 'ip'}
                          ]
                      }}
        self.snapshot = {'id': 'fake_snapshot_uuid',
                         'project_id': 'fake_tenant_id',
                         'share_id': 'fake_share_id',
                         'share': self.share
                         }
        self.security_service = {'id': 'fake_id',
                                 'domain': 'FAKE',
                                 'server': 'fake_server',
                                 'user': 'fake_user',
                                 'password': 'fake_password'}
        self.share_server = {
            'backend_details': {
                'vserver_name': 'fake_vserver'
            }
        }
        self.helper = mock.Mock()
        self.driver._helpers = {'FAKE': self.helper}
        self.driver._licenses = ['fake']

        self.network_info = {
            'server_id': 'fake_server_id',
            'cidr': '10.0.0.0/24',
            'security_services': ['fake_ldap', 'fake_kerberos', 'fake_ad', ],
            'segmentation_id': '1000',
            'network_allocations': [
                {'id': 'fake_na_id_1', 'ip_address': 'fake_ip_1', },
                {'id': 'fake_na_id_2', 'ip_address': 'fake_ip_2', },
            ],
        }

    def test_create_vserver(self):
        res = naapi.NaElement('fake')
        res.add_new_child('aggregate-name', 'aggr')
        self.driver.configuration.netapp_root_volume_aggregate = 'root'
        fake_aggrs = mock.Mock()
        fake_aggrs.get_child_by_name.return_value = fake_aggrs
        fake_aggrs.get_children.return_value = [res]
        self.driver._client.send_request = mock.Mock(return_value=fake_aggrs)
        vserver_create_args = {
            'vserver-name': 'os_fake_net_id',
            'root-volume-security-style': 'unix',
            'root-volume-aggregate': 'root',
            'root-volume': 'root',
            'name-server-switch': {
                'nsswitch': 'file'
            }
        }
        vserver_modify_args = {
            'aggr-list': [
                {'aggr-name': 'aggr'}
            ],
            'vserver-name': 'os_fake_net_id'}
        self.driver._create_vserver('os_fake_net_id')
        self.driver._client.send_request.assert_has_calls([
            mock.call('vserver-create', vserver_create_args),
            mock.call('aggr-get-iter'),
            mock.call('vserver-modify', vserver_modify_args),
        ]
        )

    def test_update_share_stats(self):
        """Retrieve status info from share volume group."""
        fake_aggr1_struct = {
            'aggr-space-attributes': {
                'size-total': '3774873600',
                'size-available': '3688566784'
            }
        }
        fake_aggr2_struct = {
            'aggr-space-attributes': {
                'size-total': '943718400',
                'size-available': '45506560'
            }
        }

        fake_aggr1 = naapi.NaElement('root')
        fake_aggr1.translate_struct(fake_aggr1_struct)

        fake_aggr2 = naapi.NaElement('root')
        fake_aggr2.translate_struct(fake_aggr2_struct)
        self.driver._find_match_aggregates = mock.Mock(
            return_value=[fake_aggr1, fake_aggr2])
        self.driver._update_share_stats()
        res = self.driver._stats

        expected = {}
        expected["share_backend_name"] = self.driver.backend_name
        expected["share_driver_mode"] = self.driver.mode
        expected["vendor_name"] = 'NetApp'
        expected["driver_version"] = '1.0'
        expected["storage_protocol"] = 'NFS_CIFS'
        expected['total_capacity_gb'] = 4
        expected['free_capacity_gb'] = 3
        expected['reserved_percentage'] = 0
        expected['QoS_support'] = False
        self.assertDictMatch(expected, res)

    def test_setup_server(self):
        self.driver._vserver_create_if_not_exists = mock.Mock(
            return_value='fake_vserver')
        result = self.driver.setup_server({'server_id': 'fake_vserver'})
        self.assertEqual(result, {'vserver_name': 'fake_vserver'})

    def test_vserver_create_if_not_exists_1(self):
        # server exists, lifs ok, all sec services
        nodes = ['fake_node_1', 'fake_node_2', ]
        port = 'fake_port'
        ip1 = self.network_info['network_allocations'][0]['ip_address']
        ip2 = self.network_info['network_allocations'][1]['ip_address']
        vserver_name = \
            self.driver.configuration.netapp_vserver_name_template % \
            self.network_info['server_id']
        self.stubs.Set(self.driver.db, 'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.driver, '_vserver_exists',
                       mock.Mock(return_value=True))
        self.stubs.Set(self.driver, '_get_cluster_nodes',
                       mock.Mock(return_value=nodes))
        self.stubs.Set(self.driver, '_get_node_data_port',
                       mock.Mock(return_value=port))
        self.stubs.Set(self.driver, '_create_lif_if_not_exists', mock.Mock())
        self.stubs.Set(self.driver, '_enable_nfs', mock.Mock())
        self.stubs.Set(self.driver, '_setup_security_services', mock.Mock())

        returned_data = self.driver._vserver_create_if_not_exists(
            self.network_info)

        self.assertEqual(returned_data, vserver_name)
        self.driver.db.share_server_backend_details_set.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      self.network_info['server_id'],
                      {'vserver_name': vserver_name}),
        ])
        self.driver._vserver_exists.assert_has_calls([mock.call(vserver_name)])
        self.driver._get_cluster_nodes.assert_has_calls([])
        self.driver._get_node_data_port.assert_has_calls([
            mock.call(nodes[0]),
            mock.call(nodes[1]),
        ])
        self.driver._create_lif_if_not_exists.assert_has_calls([
            mock.call(vserver_name,
                      self.network_info['network_allocations'][0]['id'],
                      self.network_info['segmentation_id'],
                      nodes[0], port, ip1, '255.255.255.0', mock.ANY),
            mock.call(vserver_name,
                      self.network_info['network_allocations'][1]['id'],
                      self.network_info['segmentation_id'],
                      nodes[1], port, ip2, '255.255.255.0', mock.ANY),
        ])
        self.driver._enable_nfs.assert_has_calls([mock.call(mock.ANY)])
        self.driver._setup_security_services.assert_has_calls([
            mock.call(self.network_info.get('security_services'),
                      mock.ANY, vserver_name),
        ])

    def test_vserver_create_if_not_exists_2(self):
        # server does not exist, lifs ok, no sec services
        network_info = copy.deepcopy(self.network_info)
        network_info['security_services'] = []
        nodes = ['fake_node_1', 'fake_node_2', ]
        port = 'fake_port'
        ip1 = network_info['network_allocations'][0]['ip_address']
        ip2 = network_info['network_allocations'][1]['ip_address']
        vserver_name = \
            self.driver.configuration.netapp_vserver_name_template % \
            network_info['server_id']
        self.stubs.Set(self.driver.db, 'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.driver, '_vserver_exists',
                       mock.Mock(return_value=False))
        self.stubs.Set(self.driver, '_create_vserver', mock.Mock())
        self.stubs.Set(self.driver, '_get_cluster_nodes',
                       mock.Mock(return_value=nodes))
        self.stubs.Set(self.driver, '_get_node_data_port',
                       mock.Mock(return_value=port))
        self.stubs.Set(self.driver, '_create_lif_if_not_exists', mock.Mock())
        self.stubs.Set(self.driver, '_enable_nfs', mock.Mock())

        returned_data = self.driver._vserver_create_if_not_exists(network_info)

        self.assertEqual(returned_data, vserver_name)
        self.driver.db.share_server_backend_details_set.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      self.network_info['server_id'],
                      {'vserver_name': vserver_name}),
        ])
        self.driver._vserver_exists.assert_has_calls([mock.call(vserver_name)])
        self.driver._create_vserver.assert_has_calls([mock.call(vserver_name)])
        self.driver._get_cluster_nodes.assert_has_calls([])
        self.driver._get_node_data_port.assert_has_calls([
            mock.call(nodes[0]),
            mock.call(nodes[1]),
        ])
        self.driver._create_lif_if_not_exists.assert_has_calls([
            mock.call(vserver_name,
                      network_info['network_allocations'][0]['id'],
                      network_info['segmentation_id'],
                      nodes[0], port, ip1, '255.255.255.0', mock.ANY),
            mock.call(vserver_name,
                      network_info['network_allocations'][1]['id'],
                      network_info['segmentation_id'],
                      nodes[1], port, ip2, '255.255.255.0', mock.ANY),
        ])
        self.driver._enable_nfs.assert_has_calls([mock.call(mock.ANY)])

    def test_vserver_create_if_not_exists_3(self):
        # server does not exist, lifs ok, one sec service
        network_info = copy.deepcopy(self.network_info)
        network_info['security_services'] = self.network_info[
            'security_services'][0]
        nodes = ['fake_node_1', 'fake_node_2', ]
        port = 'fake_port'
        ip1 = network_info['network_allocations'][0]['ip_address']
        ip2 = network_info['network_allocations'][1]['ip_address']
        vserver_name = \
            self.driver.configuration.netapp_vserver_name_template % \
            network_info['server_id']
        self.stubs.Set(self.driver.db, 'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.driver, '_vserver_exists',
                       mock.Mock(return_value=False))
        self.stubs.Set(self.driver, '_create_vserver', mock.Mock())
        self.stubs.Set(self.driver, '_get_cluster_nodes',
                       mock.Mock(return_value=nodes))
        self.stubs.Set(self.driver, '_get_node_data_port',
                       mock.Mock(return_value=port))
        self.stubs.Set(self.driver, '_create_lif_if_not_exists', mock.Mock())
        self.stubs.Set(self.driver, '_enable_nfs', mock.Mock())
        self.stubs.Set(self.driver, '_setup_security_services', mock.Mock())

        returned_data = self.driver._vserver_create_if_not_exists(network_info)

        self.assertEqual(returned_data, vserver_name)
        self.driver.db.share_server_backend_details_set.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      self.network_info['server_id'],
                      {'vserver_name': vserver_name}),
        ])
        self.driver._vserver_exists.assert_has_calls([mock.call(vserver_name)])
        self.driver._create_vserver.assert_has_calls([mock.call(vserver_name)])
        self.driver._get_cluster_nodes.assert_has_calls([])
        self.driver._get_node_data_port.assert_has_calls([
            mock.call(nodes[0]),
            mock.call(nodes[1]),
        ])
        self.driver._create_lif_if_not_exists.assert_has_calls([
            mock.call(vserver_name,
                      network_info['network_allocations'][0]['id'],
                      network_info['segmentation_id'],
                      nodes[0], port, ip1, '255.255.255.0', mock.ANY),
            mock.call(vserver_name,
                      network_info['network_allocations'][1]['id'],
                      network_info['segmentation_id'],
                      nodes[1], port, ip2, '255.255.255.0', mock.ANY),
        ])
        self.driver._enable_nfs.assert_has_calls([mock.call(mock.ANY)])
        self.driver._setup_security_services.assert_has_calls([
            mock.call(network_info.get('security_services'),
                      mock.ANY, vserver_name),
        ])

    def test_setup_security_services(self):
        fake_sevice_ldap = {'type': 'ldap'}
        fake_sevice_krb = {'type': 'kerberos'}
        fake_sevice_ad = {'type': 'active_directory'}
        vserver_name = 'fake_vserver'
        modify_args = {
            'name-mapping-switch': {'nmswitch': 'ldap,file'},
            'name-server-switch': {'nsswitch': 'ldap,file'},
            'vserver-name': vserver_name,
        }
        self.driver._configure_kerberos = mock.Mock()
        self.driver._configure_ldap = mock.Mock()
        self.driver._configure_active_directory = mock.Mock()

        self.driver._setup_security_services(
            [fake_sevice_ad, fake_sevice_krb, fake_sevice_ldap],
            self._vserver_client, vserver_name)

        self.driver._client.send_request.assert_called_once_with(
            'vserver-modify', modify_args)
        self.driver._configure_active_directory.assert_called_once_with(
            fake_sevice_ad, self._vserver_client, vserver_name)
        self.driver._configure_kerberos.assert_called_once_with(
            vserver_name,
            fake_sevice_krb,
            self._vserver_client,
        )
        self.driver._configure_ldap.assert_called_once_with(
            fake_sevice_ldap, self._vserver_client)

    def test_get_network_allocations_number(self):
        res = mock.Mock()
        res.get_child_content.return_value = '5'
        self.driver._client.send_request = mock.Mock(return_value=res)
        self.assertEqual(self.driver.get_network_allocations_number(), 5)

    def test_delete_vserver_without_net_info(self):
        el = naapi.NaElement('fake')
        el['num-records'] = 1
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self._vserver_client.send_request = mock.Mock(return_value=el)
        self.driver._delete_vserver('fake', self._vserver_client)
        self._vserver_client.send_request.assert_has_calls([
            mock.call('volume-offline', {'name': 'root'}),
            mock.call('volume-destroy', {'name': 'root'})
        ])
        self.driver._client.send_request.assert_called_once_with(
            'vserver-destroy', {'vserver-name': 'fake'})

    def test_delete_vserver_with_net_info(self):
        el = naapi.NaElement('fake')
        el['num-records'] = 1
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self._vserver_client.send_request = mock.Mock(return_value=el)
        security_services = [
            {'user': 'admin',
             'password': 'pass',
             'type': 'active_directory'}
        ]
        self.driver._delete_vserver('fake',
                                    self._vserver_client,
                                    security_services=security_services)
        self._vserver_client.send_request.assert_has_calls([
            mock.call('volume-get-iter'),
            mock.call('volume-offline', {'name': 'root'}),
            mock.call('volume-destroy', {'name': 'root'}),
            mock.call('cifs-server-delete', {'admin-username': 'admin',
                                             'admin-password': 'pass'})
        ])
        self.driver._client.send_request.assert_called_once_with(
            'vserver-destroy', {'vserver-name': 'fake'})

    def test_delete_vserver_has_shares(self):
        el = naapi.NaElement('fake')
        el['num-records'] = 3
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self._vserver_client.send_request = mock.Mock(return_value=el)
        self.assertRaises(exception.NetAppException,
                          self.driver._delete_vserver, 'fake',
                          self._vserver_client)

    def test_delete_vserver_without_root_volume(self):
        el = naapi.NaElement('fake')
        el['num-records'] = '0'
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self._vserver_client.send_request = mock.Mock(return_value=el)
        self.driver._delete_vserver('fake', self._vserver_client)
        self.driver._client.send_request.assert_called_once_with(
            'vserver-destroy', {'vserver-name': 'fake'})

    def test_delete_vserver_does_not_exists(self):
        self.driver._vserver_exists = mock.Mock(return_value=False)
        self.driver._delete_vserver('fake', self._vserver_client)
        self.assertEqual(self.driver._client.send_request.called, False)

    def test_vserver_exists_true(self):
        el = naapi.NaElement('fake')
        el['num-records'] = '0'
        self.driver._client.send_request = mock.Mock(return_value=el)
        self.assertEqual(self.driver._vserver_exists('fake_vserver'), False)
        self.driver._client.send_request.assert_called_once_with(
            'vserver-get-iter', {'query': {
                'vserver-info': {
                    'vserver-name': 'fake_vserver'
                }
            }
            }
        )

    def test_vserver_exists_false(self):
        el = naapi.NaElement('fake')
        el['num-records'] = '1'
        self.driver._client.send_request = mock.Mock(return_value=el)
        self.assertEqual(self.driver._vserver_exists('fake_vserver'), True)
        self.driver._client.send_request.assert_called_once_with(
            'vserver-get-iter', {'query': {
                'vserver-info': {
                    'vserver-name': 'fake_vserver'
                }
            }
            }
        )

    def test_create_net_iface(self):
        self.driver._create_net_iface('1.1.1.1', '255.255.255.0', '200',
                                      'node', 'port', 'vserver-name', 'all_id')
        vlan_args = {
            'vlan-info': {
                'parent-interface': 'port',
                'node': 'node',
                'vlanid': '200'}
        }
        interface_args = {
            'address': '1.1.1.1',
            'administrative-status': 'up',
            'data-protocols': [
                {'data-protocol': 'nfs'},
                {'data-protocol': 'cifs'}
            ],
            'home-node': 'node',
            'home-port': 'port-200',
            'netmask': '255.255.255.0',
            'interface-name': 'os_all_id',
            'role': 'data',
            'vserver': 'vserver-name',
        }
        self.driver._client.send_request.assert_has_calls([
            mock.call('net-vlan-create', vlan_args),
            mock.call('net-interface-create', interface_args),
        ])

    def test_enable_nfs(self):
        self.driver._enable_nfs(self._vserver_client)
        export_args = {
            'client-match': '0.0.0.0/0',
            'policy-name': 'default',
            'ro-rule': {
                'security-flavor': 'any'
            },
            'rw-rule': {
                'security-flavor': 'any'
            }
        }
        self._vserver_client.send_request.assert_has_calls(
            [mock.call('nfs-enable'),
             mock.call('nfs-service-modify', {'is-nfsv40-enabled': 'true'}),
             mock.call('export-rule-create', export_args)]
        )

    def test_configure_ldap(self):
        conf_name = hashlib.md5('fake_id').hexdigest()
        client_args = {
            'ldap-client-config': conf_name,
            'servers': {
                'ip-address': 'fake_server'
            },
            'tcp-port': '389',
            'schema': 'RFC-2307',
            'bind-password': 'fake_password'
        }
        config_args = {'client-config': conf_name,
                       'client-enabled': 'true'}
        self.driver._configure_ldap(self.security_service,
                                    self._vserver_client)
        self._vserver_client.send_request.assert_has_calls([
            mock.call('ldap-client-create', client_args),
            mock.call('ldap-config-create', config_args)])

    def test_configure_kerberos(self):
        kerberos_args = {'admin-server-ip': 'fake_server',
                         'admin-server-port': '749',
                         'clock-skew': '5',
                         'comment': '',
                         'config-name': 'fake_id',
                         'kdc-ip': 'fake_server',
                         'kdc-port': '88',
                         'kdc-vendor': 'other',
                         'password-server-ip': 'fake_server',
                         'password-server-port': '464',
                         'realm': 'FAKE'}
        spn = 'nfs/fake-vserver.FAKE@FAKE'
        kerberos_modify_args = {'admin-password': 'fake_password',
                                'admin-user-name': 'fake_user',
                                'interface-name': 'fake_lif',
                                'is-kerberos-enabled': 'true',
                                'service-principal-name': spn
                                }
        self.driver._get_lifs = mock.Mock(return_value=['fake_lif'])
        self.driver._configure_dns = mock.Mock(return_value=['fake_lif'])
        self.driver._configure_kerberos('fake_vserver', self.security_service,
                                        self._vserver_client)
        self.driver._client.send_request.assert_called_once_with(
            'kerberos-realm-create', kerberos_args)
        self._vserver_client.send_request.assert_called_once_with(
            'kerberos-config-modify', kerberos_modify_args)

    def test_configure_active_directory(self):
        vserver_name = 'fake_cifs_server_name'
        # cifs_server is made of first seven symbols and end six symbols
        # separated by two dots.
        cifs_server = 'FAKE_CI..R_NAME'
        self.driver._configure_dns = mock.Mock()
        self.driver._configure_active_directory(
            self.security_service, self._vserver_client, vserver_name)
        arguments = {
            'admin-username': 'fake_user',
            'admin-password': 'fake_password',
            'force-account-overwrite': 'true',
            'cifs-server': cifs_server,
            'domain': 'FAKE',
        }
        self.driver._configure_dns.assert_called_with(
            self.security_service, self._vserver_client)
        self._vserver_client.send_request.assert_called_with(
            'cifs-server-create', arguments)

    def test_configure_active_directory_error_configuring(self):
        vserver_name = 'fake_cifs_server_name'
        # cifs_server is made of first seven symbols and end six symbols
        # separated by two dots.
        cifs_server = 'FAKE_CI..R_NAME'
        arguments = {
            'admin-username': 'fake_user',
            'admin-password': 'fake_password',
            'force-account-overwrite': 'true',
            'cifs-server': cifs_server,
            'domain': 'FAKE',
        }
        self.driver._configure_dns = mock.Mock()
        self.stubs.Set(self._vserver_client, 'send_request',
                       mock.Mock(side_effect=naapi.NaApiError()))

        self.assertRaises(
            exception.NetAppException,
            self.driver._configure_active_directory,
            self.security_service,
            self._vserver_client,
            vserver_name,
        )

        self.driver._configure_dns.assert_called_with(
            self.security_service, self._vserver_client)
        self._vserver_client.send_request.assert_called_once_with(
            'cifs-server-create', arguments)

    def test_allocate_container(self):
        root = naapi.NaElement('root')
        attributes = naapi.NaElement('attributes')
        vserver_info = naapi.NaElement('vserver-info')
        vserver_aggr_info_list = naapi.NaElement('vserver-aggr-info-list')
        for i in range(1, 4):
            vserver_aggr_info_list.add_node_with_children(
                'aggr-attributes', **{'aggr-name': 'fake%s' % i,
                                      'aggr-availsize': '%s' % i})
        vserver_info.add_child_elem(vserver_aggr_info_list)
        attributes.add_child_elem(vserver_info)
        root.add_child_elem(attributes)
        root.add_new_child('attributes', None)
        self._vserver_client.send_request = mock.Mock(return_value=root)
        self.driver._allocate_container(self.share, 'vserver',
                                        self._vserver_client)
        args = {'containing-aggr-name': 'fake3',
                'size': '1g',
                'volume': 'share_fake_uuid',
                'junction-path': '/share_fake_uuid'
                }
        self._vserver_client.send_request.assert_called_with(
            'volume-create', args)

    def test_allocate_container_from_snapshot(self):
        self.driver._allocate_container_from_snapshot(self.share,
                                                      self.snapshot,
                                                      'vserver',
                                                      self._vserver_client)
        args = {'volume': 'share_fake_uuid',
                'parent-volume': 'share_fake_share_id',
                'parent-snapshot': 'share_snapshot_fake_snapshot_uuid',
                'junction-path': '/share_fake_uuid'}
        self._vserver_client.send_request.assert_called_with(
            'volume-clone-create', args)

    def test_deallocate_container(self):
        self.driver._deallocate_container(self.share, self._vserver_client)
        self._vserver_client.send_request.assert_has_calls([
            mock.call('volume-unmount',
                      {'volume-name': 'share_fake_uuid'}),
            mock.call('volume-offline',
                      {'name': 'share_fake_uuid'}),
            mock.call('volume-destroy',
                      {'name': 'share_fake_uuid'})
        ])

    def test_create_export(self):
        self.helper.create_share = mock.Mock(return_value="fake-location")
        net_info = {
            'attributes-list': {
                'net-interface-info': {'address': 'ip'}},
            'num-records': '1'}
        ifaces = naapi.NaElement('root')
        ifaces.translate_struct(net_info)
        self._vserver_client.send_request = mock.Mock(return_value=ifaces)
        export_location = self.driver._create_export(
            self.share, 'vserver', self._vserver_client)
        self.helper.create_share.assert_called_once_with(
            "share_%s" % self.share['id'], 'ip')
        self.assertEqual(export_location, "fake-location")

    def test_create_share(self):
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self.driver._allocate_container = allocate = mock.Mock()
        self.driver._create_export = create_export = mock.Mock()
        self.driver.create_share(self._context, self.share,
                                 share_server=self.share_server)
        allocate.assert_called_once_with(self.share,
                                         'fake_vserver',
                                         self._vserver_client)
        create_export.assert_called_once_with(self.share,
                                              'fake_vserver',
                                              self._vserver_client)

    def test_create_share_fails_without_server(self):
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self.assertRaises(exception.NetAppException,
                          self.driver.create_share,
                          self._context,
                          self.share)

    def test_create_share_fails_vserver_unavailable(self):
        self.driver._vserver_exists = mock.Mock(return_value=False)
        self.assertRaises(exception.VserverUnavailable,
                          self.driver.create_share,
                          self._context,
                          self.share,
                          share_server=self.share_server)

    def test_create_share_fails_vserver_name_missing(self):
        self.driver._vserver_exists = mock.Mock(return_value=False)
        self.assertRaises(exception.NetAppException,
                          self.driver.create_share,
                          self._context,
                          self.share,
                          share_server={'backend_details': None})

    def test_create_snapshot(self):
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self.driver.create_snapshot(self._context, self.snapshot,
                                    share_server=self.share_server)
        self._vserver_client.send_request.assert_called_once_with(
            'snapshot-create',
            {'volume': 'share_fake_share_id',
             'snapshot': 'share_snapshot_fake_snapshot_uuid'})

    def test_delete_share(self):
        resp = mock.Mock()
        resp.get_child_content.return_value = 1
        self._vserver_client.send_request = mock.Mock(return_value=resp)
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self.driver.delete_share(self._context, self.share,
                                 share_server=self.share_server)
        self.helper.delete_share.assert_called_once_with(self.share)

    def test_allow_access(self):
        access = "1.2.3.4"
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self.driver.allow_access(self._context, self.share, access,
                                 share_server=self.share_server)
        self.helper.allow_access.assert_called_ince_with(self._context,
                                                         self.share, access)

    def test_deny_access(self):
        access = "1.2.3.4"
        self.driver._vserver_exists = mock.Mock(return_value=True)
        self.driver.deny_access(self._context, self.share, access,
                                share_server=self.share_server)
        self.helper.deny_access.assert_called_ince_with(self._context,
                                                        self.share, access)

    def test_teardown_server(self):
        self.driver._delete_vserver = mock.Mock()
        sec_services = [{'fake': 'fake'}]
        self.driver.teardown_server(server_details={'vserver_name': 'fake'},
                                    security_services=sec_services)
        self.driver._delete_vserver.assert_called_once_with(
            'fake', self._vserver_client, security_services=sec_services)

    def test_ensure_share(self):
        self.driver.ensure_share(
            self._context, self.share, share_server=self.share_server)

    def test_licenses(self):
        licenses_dict = {
            'licenses': {
                'fake_license_1': {
                    'package': 'Fake_License_1',
                },
                'fake_license_2': {
                    'package': 'Fake_License_2',
                },
            },
        }
        licenses = naapi.NaElement('fake_licenses_as_response')
        licenses.translate_struct(licenses_dict)

        self.stubs.Set(self.driver._client, 'send_request',
                       mock.Mock(return_value=licenses))
        self.stubs.Set(driver.LOG, 'info', mock.Mock())

        response = self.driver._check_licenses()

        self.driver._client.send_request.assert_called_once_with(
            'license-v2-list-info')
        driver.LOG.info.assert_called_once_with(mock.ANY, mock.ANY)
        self.assertEqual(response, ['fake_license_1', 'fake_license_2'])

    def test_licenses_exception_raise(self):
        self.stubs.Set(self.driver._client, 'send_request',
                       mock.Mock(side_effect=naapi.NaApiError()))
        self.stubs.Set(driver.LOG, 'error', mock.Mock())

        self.driver._check_licenses()

        self.driver._client.send_request.assert_called_once_with(
            'license-v2-list-info')
        driver.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)


class NetAppNFSHelperTestCase(test.TestCase):
    """Test suite for NetApp Cluster Mode NFS helper."""

    def setUp(self):
        super(NetAppNFSHelperTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.client = mock.Mock()
        self.name = 'fake_share_name'
        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': self.name,
                      'size': 1,
                      'export_location': 'location:/%s' % self.name,
                      'share_server_id': 'fake-share-srv-id',
                      'share_proto': 'fake'}
        self.helper = driver.NetAppClusteredNFSHelper()
        self.helper._client = mock.Mock()
        self.helper._client.send_request = mock.Mock()

    def test_create_share(self):
        export_ip = 'fake_export_ip'
        junction = 'fake-vserver-location'
        self.stubs.Set(self.helper._client, 'send_request', mock.Mock())
        self.helper._client.send_request().get_child_by_name = mock.Mock()
        self.helper._client.send_request().get_child_by_name().get_content = (
            mock.Mock(side_effect=lambda: junction))
        self.stubs.Set(self.helper, 'add_rules', mock.Mock())

        location = self.helper.create_share(self.share['name'], export_ip)

        self.helper._client.send_request.has_calls(
            mock.call(
                'volume-get-volume-path',
                {'is-style-cifs': 'false', 'volume': self.share['name']},
            ),
        )
        self.helper.add_rules.assert_called_once_with(
            junction, ['localhost'])
        self.assertEqual(location, export_ip + ':' + junction)

    def test_add_rules(self):
        volume_path = "fake_volume_path"
        rules = ['1.2.3.4', '4.3.2.1']
        self.helper.nfs_exports_with_prefix = False

        self.helper.add_rules(volume_path, rules)

        self.helper._client.send_request.assert_called_once_with(
            'nfs-exportfs-append-rules-2', mock.ANY)
        self.assertEqual(self.helper.nfs_exports_with_prefix, False)

    def test_add_rules_changed_pathname(self):
        volume_path = "fake_volume_path"
        rules = ['1.2.3.4', '4.3.2.1']
        self.helper.nfs_exports_with_prefix = False

        def raise_exception_13114(*args, **kwargs):
            pathname = args[1]['rules']['exports-rule-info-2']['pathname']
            if pathname.startswith(volume_path):
                raise naapi.NaApiError('13114')

        self.stubs.Set(self.helper._client, 'send_request',
                       mock.Mock(side_effect=raise_exception_13114))

        self.helper.add_rules(volume_path, rules)

        self.helper._client.send_request.has_calls(
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
        )
        self.assertEqual(self.helper.nfs_exports_with_prefix, True)

    def test_add_rules_verify_behavior_remembering(self):
        volume_path = "fake_volume_path"
        rules = ['1.2.3.4', '4.3.2.1']
        self.helper.nfs_exports_with_prefix = False

        def raise_exception_13114(*args, **kwargs):
            pathname = args[1]['rules']['exports-rule-info-2']['pathname']
            if (pathname.startswith(volume_path) and
                    not self.helper.nfs_exports_with_prefix):
                raise naapi.NaApiError('13114')

        self.stubs.Set(self.helper._client, 'send_request',
                       mock.Mock(side_effect=raise_exception_13114))

        self.helper.add_rules(volume_path, rules)

        self.helper._client.send_request.has_calls(
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
        )
        self.assertEqual(self.helper.nfs_exports_with_prefix, True)

        self.helper.add_rules(volume_path, rules)

        self.helper._client.send_request.has_calls(
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY),
        )
        self.assertEqual(self.helper.nfs_exports_with_prefix, True)

    def test_delete_share(self):
        self.helper.delete_share(self.share)
        self.helper._client.send_request.assert_called_once_with(
            'nfs-exportfs-delete-rules', mock.ANY)

    def test_allow_access(self):
        access = {'access_to': '1.2.3.4',
                  'access_type': 'ip'}
        root = naapi.NaElement('root')
        rules = naapi.NaElement('rules')
        root.add_child_elem(rules)
        self.helper._client.send_request = mock.Mock(return_value=root)
        self.helper.allow_access(self._context, self.share, access)
        self.helper._client.send_request.assert_has_calls([
            mock.call('nfs-exportfs-list-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY)
        ])

    def test_deny_access(self):
        access = {'access_to': '1.2.3.4',
                  'access_type': 'ip'}
        root = naapi.NaElement('root')
        rules = naapi.NaElement('rules')
        root.add_child_elem(rules)
        self.helper._client.send_request = mock.Mock(return_value=root)
        self.helper.allow_access(self._context, self.share, access)
        self.helper._client.send_request.assert_has_calls([
            mock.call('nfs-exportfs-list-rules-2', mock.ANY),
            mock.call('nfs-exportfs-append-rules-2', mock.ANY)
        ])


class NetAppCIFSHelperTestCase(test.TestCase):
    """Test suite for NetApp Cluster Mode CIFS helper."""

    def setUp(self):
        super(NetAppCIFSHelperTestCase, self).setUp()
        self._context = context.get_admin_context()
        self.name = 'fake_share_name'
        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': self.name,
                      'size': 1,
                      'export_location': '//location/%s' % self.name,
                      'share_proto': 'fake'}
        self.helper = driver.NetAppClusteredCIFSHelper()
        self.stubs.Set(self.helper, '_client', mock.Mock())
        self.stubs.Set(self.helper._client, 'send_request', mock.Mock())

    def test_create_share(self):
        self.helper.create_share(self.name, '1.1.1.1')
        self.helper._client.send_request.assert_has_calls([
            mock.call(
                'cifs-share-create',
                {'path': '/%s' % self.name, 'share-name': self.name},
            ),
            mock.call(
                'cifs-share-access-control-delete',
                {'user-or-group': 'Everyone', 'share': self.name},
            )
        ])

    def test_delete_share(self):
        self.helper.delete_share(self.share)
        self.helper._client.send_request.assert_called_with(
            'cifs-share-delete', {'share-name': self.name})

    def test_allow_access_user_type(self):
        access = {'access_to': 'fake_access', 'access_type': 'user'}
        self.helper.allow_access(self._context, self.share, access)
        self.helper._client.send_request.assert_called_once_with(
            'cifs-share-access-control-create',
            {
                'permission': 'full_control',
                'share': self.name,
                'user-or-group': access['access_to'],
            },
        )

    def test_allow_access_user_type_rule_already_present(self):
        self.stubs.Set(self.helper._client, 'send_request',
                       mock.Mock(side_effect=naapi.NaApiError('13130')))
        access = {'access_to': 'fake_access', 'access_type': 'user'}
        self.assertRaises(
            exception.ShareAccessExists,
            self.helper.allow_access,
            self._context,
            self.share,
            access,
        )
        self.helper._client.send_request.assert_called_once_with(
            'cifs-share-access-control-create',
            {
                'permission': 'full_control',
                'share': self.name,
                'user-or-group': access['access_to'],
            },
        )

    def test_allow_access_ip_type(self):
        # IP rules are not supported by Cluster Mode driver
        self.assertRaises(
            exception.NetAppException,
            self.helper.allow_access,
            self._context,
            self.share,
            {'access_to': 'fake_access', 'access_type': 'ip'},
        )

    def test_allow_access_fake_type(self):
        self.assertRaises(
            exception.NetAppException,
            self.helper.allow_access,
            self._context,
            self.share,
            {'access_to': 'fake_access', 'access_type': 'fake_type'},
        )

    def test_deny_access(self):
        access = {'access_to': 'fake_access', 'access_type': 'user'}
        self.helper.deny_access(self._context, self.share, access)
        self.helper._client.send_request.assert_called_once_with(
            'cifs-share-access-control-delete',
            {'user-or-group': access['access_to'], 'share': self.name},
        )

    def test_deny_access_exception_raised(self):
        self.stubs.Set(self.helper, '_restrict_access',
                       mock.Mock(side_effect=naapi.NaApiError()))
        self.assertRaises(
            naapi.NaApiError,
            self.helper.deny_access,
            self._context,
            self.share,
            {'access_to': 'fake_access'},
        )

    def test_get_target(self):
        result = self.helper.get_target(self.share)
        self.assertEqual(result, 'location')
