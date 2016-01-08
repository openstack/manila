#    Copyright 2014 Mirantis Inc.
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

import ddt
import mock
from novaclient import exceptions as nova_exception
from novaclient import utils
from novaclient.v2 import servers as nova_servers

from manila.compute import nova
from manila import context
from manila import exception
from manila import test
from manila.volume import cinder


class Volume(object):
    def __init__(self, volume_id):
        self.id = volume_id
        self.name = volume_id


class Network(object):
    def __init__(self, net_id):
        self.id = net_id
        self.label = 'fake_label_%s' % net_id


class FakeNovaClient(object):
    class Servers(object):
        def get(self, instance_id):
            return {'id': instance_id}

        def list(self, *args, **kwargs):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def create(self, *args, **kwargs):
            return {'id': 'created_id'}

        def __getattr__(self, item):
            return None

    class Volumes(object):
        def get(self, volume_id):
            return Volume(volume_id)

        def list(self, detailed, *args, **kwargs):
            return [{'id': 'id1'}, {'id': 'id2'}]

        def create(self, *args, **kwargs):
            return {'id': 'created_id'}

        def __getattr__(self, item):
            return None

    class Networks(object):
        def get(self, net_id):
            return Network(net_id)

    class FixedIPs(object):
        def get(self, fixed_ip):
            return dict(address=fixed_ip)

        def reserve(self, fixed_ip):
            return None

        def unreserve(self, fixed_ip):
            return None

    def __init__(self):
        self.servers = self.Servers()
        self.volumes = self.Volumes()
        self.keypairs = self.servers
        self.networks = self.Networks()
        self.fixed_ips = self.FixedIPs()


@nova.translate_server_exception
def decorated_by_translate_server_exception(self, context, instance_id, exc):
    if exc:
        raise exc(instance_id)
    else:
        return 'OK'


@ddt.ddt
class TranslateServerExceptionTestCase(test.TestCase):

    def test_translate_server_exception(self):
        result = decorated_by_translate_server_exception(
            'foo_self', 'foo_ctxt', 'foo_instance_id', None)
        self.assertEqual('OK', result)

    def test_translate_server_exception_not_found(self):
        self.assertRaises(
            exception.InstanceNotFound,
            decorated_by_translate_server_exception,
            'foo_self', 'foo_ctxt', 'foo_instance_id', nova_exception.NotFound)

    def test_translate_server_exception_bad_request(self):
        self.assertRaises(
            exception.InvalidInput,
            decorated_by_translate_server_exception,
            'foo_self', 'foo_ctxt', 'foo_instance_id',
            nova_exception.BadRequest)

    @ddt.data(
        nova_exception.HTTPNotImplemented,
        nova_exception.RetryAfterException,
        nova_exception.Unauthorized,
        nova_exception.Forbidden,
        nova_exception.MethodNotAllowed,
        nova_exception.OverLimit,
        nova_exception.RateLimit,
    )
    def test_translate_server_exception_other_exception(self, exc):
        self.assertRaises(
            exception.ManilaException,
            decorated_by_translate_server_exception,
            'foo_self', 'foo_ctxt', 'foo_instance_id', exc)


@ddt.ddt
class NovaApiTestCase(test.TestCase):
    def setUp(self):
        super(NovaApiTestCase, self).setUp()

        self.api = nova.API()
        self.novaclient = FakeNovaClient()
        self.ctx = context.get_admin_context()
        self.mock_object(nova, 'novaclient',
                         mock.Mock(return_value=self.novaclient))
        self.mock_object(nova, '_untranslate_server_summary_view',
                         lambda server: server)

    def test_server_create(self):
        result = self.api.server_create(self.ctx, 'server_name', 'fake_image',
                                        'fake_flavor', None, None, None)
        self.assertEqual('created_id', result['id'])

    def test_server_delete(self):
        self.mock_object(self.novaclient.servers, 'delete')
        self.api.server_delete(self.ctx, 'id1')
        self.novaclient.servers.delete.assert_called_once_with('id1')

    def test_server_get(self):
        instance_id = 'instance_id1'
        result = self.api.server_get(self.ctx, instance_id)
        self.assertEqual(instance_id, result['id'])

    def test_server_get_by_name_or_id(self):
        instance_id = 'instance_id1'
        server = {'id': instance_id, 'fake_key': 'fake_value'}
        self.mock_object(utils, 'find_resource',
                         mock.Mock(return_value=server))

        result = self.api.server_get_by_name_or_id(self.ctx, instance_id)

        self.assertEqual(instance_id, result['id'])
        utils.find_resource.assert_called_once_with(mock.ANY, instance_id)

    @ddt.data(
        {'nova_e': nova_exception.NotFound(404),
         'manila_e': exception.InstanceNotFound},
        {'nova_e': nova_exception.BadRequest(400),
         'manila_e': exception.InvalidInput},
    )
    @ddt.unpack
    def test_server_get_failed(self, nova_e, manila_e):
        nova.novaclient.side_effect = nova_e
        instance_id = 'instance_id'
        self.assertRaises(manila_e, self.api.server_get, self.ctx, instance_id)

    def test_server_list(self):
        self.assertEqual([{'id': 'id1'}, {'id': 'id2'}],
                         self.api.server_list(self.ctx))

    def test_server_pause(self):
        self.mock_object(self.novaclient.servers, 'pause')
        self.api.server_pause(self.ctx, 'id1')
        self.novaclient.servers.pause.assert_called_once_with('id1')

    def test_server_unpause(self):
        self.mock_object(self.novaclient.servers, 'unpause')
        self.api.server_unpause(self.ctx, 'id1')
        self.novaclient.servers.unpause.assert_called_once_with('id1')

    def test_server_suspend(self):
        self.mock_object(self.novaclient.servers, 'suspend')
        self.api.server_suspend(self.ctx, 'id1')
        self.novaclient.servers.suspend.assert_called_once_with('id1')

    def test_server_resume(self):
        self.mock_object(self.novaclient.servers, 'resume')
        self.api.server_resume(self.ctx, 'id1')
        self.novaclient.servers.resume.assert_called_once_with('id1')

    def test_server_reboot_hard(self):
        self.mock_object(self.novaclient.servers, 'reboot')
        self.api.server_reboot(self.ctx, 'id1')
        self.novaclient.servers.reboot.assert_called_once_with(
            'id1', nova_servers.REBOOT_HARD)

    def test_server_reboot_soft(self):
        self.mock_object(self.novaclient.servers, 'reboot')
        self.api.server_reboot(self.ctx, 'id1', True)
        self.novaclient.servers.reboot.assert_called_once_with(
            'id1', nova_servers.REBOOT_SOFT)

    def test_server_rebuild(self):
        self.mock_object(self.novaclient.servers, 'rebuild')
        self.api.server_rebuild(self.ctx, 'id1', 'fake_image')
        self.novaclient.servers.rebuild.assert_called_once_with('id1',
                                                                'fake_image',
                                                                None)

    def test_instance_volume_attach(self):
        self.mock_object(self.novaclient.volumes, 'create_server_volume')
        self.api.instance_volume_attach(self.ctx, 'instance_id',
                                        'vol_id', 'device')
        self.novaclient.volumes.create_server_volume.\
            assert_called_once_with('instance_id', 'vol_id', 'device')

    def test_instance_volume_detach(self):
        self.mock_object(self.novaclient.volumes, 'delete_server_volume')
        self.api.instance_volume_detach(self.ctx, 'instance_id',
                                        'att_id')
        self.novaclient.volumes.delete_server_volume.\
            assert_called_once_with('instance_id', 'att_id')

    def test_instance_volumes_list(self):
        self.mock_object(
            self.novaclient.volumes, 'get_server_volumes',
            mock.Mock(return_value=[Volume('id1'), Volume('id2')]))
        self.cinderclient = self.novaclient
        self.mock_object(cinder, 'cinderclient',
                         mock.Mock(return_value=self.novaclient))
        result = self.api.instance_volumes_list(self.ctx, 'instance_id')
        self.assertEqual(2, len(result))
        self.assertEqual('id1', result[0].id)
        self.assertEqual('id2', result[1].id)

    def test_server_update(self):
        self.mock_object(self.novaclient.servers, 'update')
        self.api.server_update(self.ctx, 'id1', 'new_name')
        self.novaclient.servers.update.assert_called_once_with('id1',
                                                               name='new_name')

    def test_update_server_volume(self):
        self.mock_object(self.novaclient.volumes, 'update_server_volume')
        self.api.update_server_volume(self.ctx, 'instance_id', 'att_id',
                                      'new_vol_id')
        self.novaclient.volumes.update_server_volume.\
            assert_called_once_with('instance_id', 'att_id', 'new_vol_id')

    def test_keypair_create(self):
        self.mock_object(self.novaclient.keypairs, 'create')
        self.api.keypair_create(self.ctx, 'keypair_name')
        self.novaclient.keypairs.create.assert_called_once_with('keypair_name')

    def test_keypair_import(self):
        self.mock_object(self.novaclient.keypairs, 'create')
        self.api.keypair_import(self.ctx, 'keypair_name', 'fake_pub_key')
        self.novaclient.keypairs.create.\
            assert_called_once_with('keypair_name', 'fake_pub_key')

    def test_keypair_delete(self):
        self.mock_object(self.novaclient.keypairs, 'delete')
        self.api.keypair_delete(self.ctx, 'fake_keypair_id')
        self.novaclient.keypairs.delete.\
            assert_called_once_with('fake_keypair_id')

    def test_keypair_list(self):
        self.assertEqual([{'id': 'id1'}, {'id': 'id2'}],
                         self.api.keypair_list(self.ctx))

    def test_fixed_ip_get(self):
        fixed_ip = 'fake_fixed_ip'
        result = self.api.fixed_ip_get(self.ctx, fixed_ip)
        self.assertIsInstance(result, dict)
        self.assertEqual(fixed_ip, result['address'])

    def test_fixed_ip_reserve(self):
        fixed_ip = 'fake_fixed_ip'
        result = self.api.fixed_ip_reserve(self.ctx, fixed_ip)
        self.assertIsNone(result)

    def test_fixed_ip_unreserve(self):
        fixed_ip = 'fake_fixed_ip'
        result = self.api.fixed_ip_unreserve(self.ctx, fixed_ip)
        self.assertIsNone(result)

    def test_network_get(self):
        net_id = 'fake_net_id'
        net = self.api.network_get(self.ctx, net_id)
        self.assertIsInstance(net, dict)
        self.assertEqual(net_id, net['id'])


class ToDictTestCase(test.TestCase):

    def test_dict_provided(self):
        fake_dict = {'foo_key': 'foo_value', 'bar_key': 'bar_value'}
        result = nova._to_dict(fake_dict)
        self.assertEqual(fake_dict, result)

    def test_obj_provided_with_to_dict_method(self):
        expected = {'foo': 'bar'}

        class FakeObj(object):
            def __init__(self):
                self.fake_attr = 'fake_attr_value'

            def to_dict(self):
                return expected

        fake_obj = FakeObj()
        result = nova._to_dict(fake_obj)
        self.assertEqual(expected, result)

    def test_obj_provided_without_to_dict_method(self):
        expected = {'foo': 'bar'}

        class FakeObj(object):
            def __init__(self):
                self.foo = expected['foo']

        fake_obj = FakeObj()
        result = nova._to_dict(fake_obj)
        self.assertEqual(expected, result)
