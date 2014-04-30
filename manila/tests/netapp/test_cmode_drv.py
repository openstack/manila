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

import hashlib
import mock

from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.netapp import api as naapi
from manila.share.drivers.netapp import cluster_mode as driver
from manila import test


class NetAppClusteredDrvTestCase(test.TestCase):
    """Tests for NetApp cmode driver.
    """
    def setUp(self):
        super(NetAppClusteredDrvTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        driver.driver.NetAppApiClient = mock.Mock()
        self.driver = driver.NetAppClusteredShareDriver(
            self._db, configuration=configuration.Configuration(None))
        self.driver._client = mock.Mock()
        self.driver._client.send_request = mock.Mock()
        self._vserver_client = mock.Mock()
        self._vserver_client.send_request = mock.Mock()
        driver.driver.NetAppApiClient = mock.Mock(
            return_value=self._vserver_client)

        self.share = {'id': 'fake_uuid',
                      'project_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'share_proto': 'fake',
                      'share_network_id': 'fake_net_id',
                      'network_info': {
                          'network_allocations': [
                              {'ip_address': 'ip'}
                          ]
                      }
        }
        self.snapshot = {'id': 'fake_snapshot_uuid',
                         'project_id': 'fake_tenant_id',
                         'share_id': 'fake_share_id',
                         'share': self.share
                         }
        self.security_service = {'id': 'fake_id',
                                 'domain': 'FAKE',
                                 'server': 'fake_server',
                                 'sid': 'fake_sid',
                                 'password': 'fake_password'}
        self.helper = mock.Mock()
        self.driver._helpers = {'FAKE': self.helper}
        self.driver._licenses = ['fake']

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
        net_info = {
            'security_services': [
                {'sid': 'admin',
                 'password': 'pass',
                 'type': 'active_directory'}
            ]
        }
        self.driver._delete_vserver('fake', self._vserver_client,
                                    network_info=net_info)
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
                                'admin-user-name': 'fake_sid',
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
        self.driver._configure_dns = mock.Mock()
        self.driver._configure_active_directory(self.security_service,
                                                self._vserver_client)
        args = {'admin-username': 'fake_sid',
                'admin-password': 'fake_password',
                'force-account-overwrite': 'true',
                'cifs-server': 'fake_server',
                'domain': 'FAKE'}
        self._vserver_client.send_request.assert_called_with(
            'cifs-server-create', args)

    def test_allocate_container(self):
        root = naapi.NaElement('root')
        attributes = naapi.NaElement('attributes')
        vserver_info = naapi.NaElement('vserver-info')
        vserver_aggr_info_list = naapi.NaElement('vserver-aggr-info-list')
        for i in range(1, 4):
            vserver_aggr_info_list.add_node_with_children('aggr-attributes',
                                              **{'aggr-name': 'fake%s' % i,
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

    def test_create_snapshot(self):
        self.driver.create_snapshot(self._context, self.snapshot)
        self._vserver_client.send_request.assert_called_once_with(
            'snapshot-create',
            {'volume': 'share_fake_share_id',
             'snapshot': 'share_snapshot_fake_snapshot_uuid'})

    def test_delete_share(self):
        resp = mock.Mock()
        resp.get_child_content.return_value = 1
        self._vserver_client.send_request = mock.Mock(return_value=resp)
        self.driver.delete_share(self._context, self.share)
        self.helper.delete_share.assert_called_once_with(self.share)

    def test_allow_access(self):
        access = "1.2.3.4"
        self.driver.allow_access(self._context, self.share, access)
        self.helper.allow_access.assert_called_ince_with(self._context,
                                                         self.share, access)

    def test_deny_access(self):
        access = "1.2.3.4"
        self.driver.deny_access(self._context, self.share, access)
        self.helper.deny_access.assert_called_ince_with(self._context,
                                                        self.share, access)

    def test_teardown_network(self):
        fake_net_info = {'id': 'fakeid'}
        self.driver._delete_vserver = mock.Mock()
        self.driver.teardown_network(fake_net_info)
        self.driver._delete_vserver.assert_called_once_with(
            'os_fakeid', self._vserver_client, network_info=fake_net_info)


class NetAppNFSHelperTestCase(test.TestCase):
    """Tests for NetApp 7mode driver.
    """
    def setUp(self):
        super(NetAppNFSHelperTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.client = mock.Mock()

        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'export_location': 'location:/path',
                      'share_proto': 'fake'}
        self.helper = driver.NetAppClusteredNFSHelper()
        self.helper._client = mock.Mock()
        self.helper._client.send_request = mock.Mock()

    def test_create_share(self):
        location = self.helper.create_share('share_name',
                                            'fake-vserver-location')
        self.helper._client.send_request.assert_called_once_with(
            'nfs-exportfs-append-rules-2', mock.ANY)
        self.assertEqual(location, 'fake-vserver-location:/share_name')

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
    """Tests for NetApp 7mode driver.
    """
    def setUp(self):
        super(NetAppCIFSHelperTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = mock.Mock()

        self.share = {'id': 'fake_uuid',
                      'tenant_id': 'fake_tenant_id',
                      'name': 'fake_name',
                      'size': 1,
                      'export_location': 'location:/path',
                      'share_proto': 'fake'}
        self.helper = driver.NetAppClusteredCIFSHelper()
        self.helper._client = mock.Mock()
        self.helper._client.send_request = mock.Mock()

    def test_create_share(self):
        self.helper.create_share('fake_name', '1.1.1.1')
        self.helper._client.send_request.assert_has_calls([
            mock.call('cifs-share-create', {'path': '/fake_name',
                                            'share-name': 'fake_name'}),
            mock.call('cifs-share-access-control-delete',
                      {'user-or-group': 'Everyone', 'share': 'fake_name'})
        ])

    def test_delete_share(self):
        self.share['export_location'] = "nfs://host/fake_name"
        self.helper.delete_share(self.share)
        self.helper._client.send_request.assert_called_with(
            'cifs-share-delete', {'share-name': 'fake_name'})

    def test_allow_access(self):
        self.helper._allow_access_for('fake_name', 'fake_share')
        self.helper._client.send_request.assert_called_with(
            'cifs-share-access-control-create', {'permission': 'full_control',
                                                 'share': 'fake_share',
                                                 'user-or-group': 'fake_name'})
