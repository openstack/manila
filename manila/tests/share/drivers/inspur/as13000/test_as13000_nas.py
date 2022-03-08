# Copyright 2018 Inspur Corp.
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

"""
Share driver test for Inspur AS13000
"""

import json
import time
from unittest import mock

import ddt
from oslo_config import cfg
import requests

from manila import context
from manila import exception
from manila.share import driver
from manila.share.drivers.inspur.as13000 import as13000_nas
from manila import test
from manila.tests import fake_share

CONF = cfg.CONF


class FakeConfig(object):
    def __init__(self, *args, **kwargs):
        self.driver_handles_share_servers = False
        self.share_driver = 'fake_share_driver_name'
        self.share_backend_name = 'fake_as13000'
        self.as13000_nas_ip = kwargs.get(
            'as13000_nas_ip', 'some_ip')
        self.as13000_nas_port = kwargs.get(
            'as13000_nas_port', 'some_port')
        self.as13000_nas_login = kwargs.get(
            'as13000_nas_login', 'username')
        self.as13000_nas_password = kwargs.get(
            'as13000_nas_password', 'password')
        self.as13000_share_pools = kwargs.get(
            'as13000_share_pools', ['fakepool'])
        self.as13000_token_available_time = kwargs.get(
            'as13000_token_available_time', 3600)
        self.network_config_group = kwargs.get(
            "network_config_group", "fake_network_config_group")
        self.admin_network_config_group = kwargs.get(
            "admin_network_config_group", "fake_admin_network_config_group")
        self.config_group = kwargs.get("config_group", "fake_config_group")
        self.reserved_share_percentage = kwargs.get(
            "reserved_share_percentage", 0)
        self.reserved_share_from_snapshot_percentage = kwargs.get(
            "reserved_share_from_snapshot_percentage", 0)
        self.reserved_share_extend_percentage = kwargs.get(
            "reserved_share_extend_percentage", 0)
        self.max_over_subscription_ratio = kwargs.get(
            "max_over_subscription_ratio", 20.0)
        self.filter_function = kwargs.get("filter_function", None)
        self.goodness_function = kwargs.get("goodness_function", None)

    def safe_get(self, key):
        return getattr(self, key)

    def append_config_values(self, *args, **kwargs):
        pass


test_config = FakeConfig()


class FakeResponse(object):
    def __init__(self, status, output):
        self.status_code = status
        self.text = 'return message'
        self._json = output

    def json(self):
        return self._json

    def close(self):
        pass


@ddt.ddt
class RestAPIExecutorTestCase(test.TestCase):
    def setUp(self):
        self.rest_api = as13000_nas.RestAPIExecutor(
            test_config.as13000_nas_ip,
            test_config.as13000_nas_port,
            test_config.as13000_nas_login,
            test_config.as13000_nas_password)
        super(RestAPIExecutorTestCase, self).setUp()

    def test_logins(self):
        mock_login = self.mock_object(self.rest_api, 'login',
                                      mock.Mock(return_value='fake_token'))
        self.rest_api.logins()
        mock_login.assert_called_once()

    def test_login(self):
        fake_response = {
            'token': 'fake_token',
            'expireTime': '7200',
            'type': 0}
        mock_sra = self.mock_object(self.rest_api, 'send_rest_api',
                                    mock.Mock(return_value=fake_response))
        result = self.rest_api.login()

        self.assertEqual('fake_token', result)

        login_params = {'name': test_config.as13000_nas_login,
                        'password': test_config.as13000_nas_password}
        mock_sra.assert_called_once_with(method='security/token',
                                         params=login_params,
                                         request_type='post')

    def test_logout(self):
        mock_sra = self.mock_object(self.rest_api, 'send_rest_api',
                                    mock.Mock(return_value=None))
        self.rest_api.logout()
        mock_sra.assert_called_once_with(
            method='security/token', request_type='delete')

    @ddt.data(True, False)
    def test_refresh_token(self, force):
        mock_login = self.mock_object(self.rest_api, 'login',
                                      mock.Mock(return_value='fake_token'))
        mock_logout = self.mock_object(self.rest_api, 'logout',
                                       mock.Mock())
        self.rest_api.refresh_token(force)
        if force is not True:
            mock_logout.assert_called_once_with()
        mock_login.assert_called_once_with()

    def test_send_rest_api(self):
        expected = {'value': 'abc'}
        mock_sa = self.mock_object(self.rest_api, 'send_api',
                                   mock.Mock(return_value=expected))
        result = self.rest_api.send_rest_api(
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        self.assertEqual(expected, result)
        mock_sa.assert_called_once_with(
            'fake_method',
            'fake_params',
            'fake_type')

    def test_send_rest_api_retry(self):
        expected = {'value': 'abc'}
        mock_sa = self.mock_object(
            self.rest_api,
            'send_api',
            mock.Mock(
                side_effect=(
                    exception.NetworkException,
                    expected)))
        # mock.Mock(side_effect=exception.NetworkException))
        mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
        result = self.rest_api.send_rest_api(
            method='fake_method',
            params='fake_params',
            request_type='fake_type'
        )
        self.assertEqual(expected, result)

        mock_sa.assert_called_with(
            'fake_method',
            'fake_params',
            'fake_type')
        mock_rt.assert_called_with(force=True)

    def test_send_rest_api_3times_fail(self):
        mock_sa = self.mock_object(
            self.rest_api, 'send_api', mock.Mock(
                side_effect=(exception.NetworkException)))
        mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_rest_api,
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        mock_sa.assert_called_with('fake_method',
                                   'fake_params',
                                   'fake_type')
        mock_rt.assert_called_with(force=True)

    def test_send_rest_api_backend_error_fail(self):
        mock_sa = self.mock_object(self.rest_api, 'send_api', mock.Mock(
            side_effect=(exception.ShareBackendException(
                'fake_error_message'))))
        mock_rt = self.mock_object(self.rest_api, 'refresh_token')
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_rest_api,
            method='fake_method',
            params='fake_params',
            request_type='fake_type')
        mock_sa.assert_called_with('fake_method',
                                   'fake_params',
                                   'fake_type')
        mock_rt.assert_not_called()

    @ddt.data(
        {'method': 'fake_method', 'request_type': 'post', 'params':
            {'fake_param': 'fake_value'}},
        {'method': 'fake_method', 'request_type': 'get', 'params':
            {'fake_param': 'fake_value'}},
        {'method': 'fake_method', 'request_type': 'delete', 'params':
            {'fake_param': 'fake_value'}},
        {'method': 'fake_method', 'request_type': 'put', 'params':
            {'fake_param': 'fake_value'}}, )
    @ddt.unpack
    def test_send_api(self, method, params, request_type):
        self.rest_api._token_pool = ['fake_token']
        if request_type in ('post', 'delete', 'put'):
            fake_output = {'code': 0, 'message': 'success'}
        elif request_type == 'get':
            fake_output = {'code': 0, 'data': 'fake_date'}

        fake_response = FakeResponse(200, fake_output)
        mock_request = self.mock_object(requests,
                                        request_type,
                                        mock.Mock(return_value=fake_response))
        self.rest_api.send_api(method,
                               params=params,
                               request_type=request_type)

        url = 'http://%s:%s/rest/%s' % (test_config.as13000_nas_ip,
                                        test_config.as13000_nas_port,
                                        method)
        headers = {'X-Auth-Token': 'fake_token'}
        mock_request.assert_called_once_with(url,
                                             data=json.dumps(params),
                                             headers=headers)

    @ddt.data({'method': r'security/token',
               'params': {'name': test_config.as13000_nas_login,
                          'password': test_config.as13000_nas_password},
               'request_type': 'post'},
              {'method': r'security/token',
               'params': None,
               'request_type': 'delete'})
    @ddt.unpack
    def test_send_api_access_success(self, method, params, request_type):
        if request_type == 'post':
            fake_value = {'code': 0, 'data': {
                'token': 'fake_token',
                'expireTime': '7200',
                'type': 0}}
            mock_requests = self.mock_object(
                requests, 'post', mock.Mock(
                    return_value=FakeResponse(
                        200, fake_value)))
            result = self.rest_api.send_api(method, params, request_type)
            self.assertEqual(fake_value['data'], result)
            mock_requests.assert_called_once_with(
                'http://%s:%s/rest/%s' %
                (test_config.as13000_nas_ip,
                 test_config.as13000_nas_port,
                 method),
                data=json.dumps(params),
                headers=None)
        if request_type == 'delete':
            fake_value = {'code': 0, 'message': 'Success!'}
            self.rest_api._token_pool = ['fake_token']
            mock_requests = self.mock_object(
                requests, 'delete', mock.Mock(
                    return_value=FakeResponse(
                        200, fake_value)))
            self.rest_api.send_api(method, params, request_type)
            mock_requests.assert_called_once_with(
                'http://%s:%s/rest/%s' %
                (test_config.as13000_nas_ip,
                 test_config.as13000_nas_port,
                 method),
                data=None,
                headers={'X-Auth-Token': 'fake_token'})

    def test_send_api_wrong_access_fail(self):
        req_params = {'method': r'security/token',
                      'params': {'name': test_config.as13000_nas_login,
                                 'password': 'fake_password'},
                      'request_type': 'post'}
        fake_value = {'message': ' User name or password error.', 'code': 400}
        mock_request = self.mock_object(
            requests, 'post', mock.Mock(
                return_value=FakeResponse(
                    200, fake_value)))
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_api,
            method=req_params['method'],
            params=req_params['params'],
            request_type=req_params['request_type'])
        mock_request.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             req_params['method']),
            data=json.dumps(
                req_params['params']),
            headers=None)

    def test_send_api_token_overtime_fail(self):
        self.rest_api._token_pool = ['fake_token']
        fake_value = {'method': 'fake_url',
                      'params': 'fake_params',
                      'reuest_type': 'post'}
        fake_out_put = {'message': 'Unauthorized access!', 'code': 301}
        mock_requests = self.mock_object(
            requests, 'post', mock.Mock(
                return_value=FakeResponse(
                    200, fake_out_put)))
        self.assertRaises(exception.NetworkException,
                          self.rest_api.send_api,
                          method='fake_url',
                          params='fake_params',
                          request_type='post')
        mock_requests.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             fake_value['method']),
            data=json.dumps('fake_params'),
            headers={
                'X-Auth-Token': 'fake_token'})

    def test_send_api_fail(self):
        self.rest_api._token_pool = ['fake_token']
        fake_output = {'code': 100, 'message': 'fake_message'}
        mock_request = self.mock_object(
            requests, 'post', mock.Mock(
                return_value=FakeResponse(
                    200, fake_output)))
        self.assertRaises(
            exception.ShareBackendException,
            self.rest_api.send_api,
            method='fake_method',
            params='fake_params',
            request_type='post')
        mock_request.assert_called_once_with(
            'http://%s:%s/rest/%s' %
            (test_config.as13000_nas_ip,
             test_config.as13000_nas_port,
             'fake_method'),
            data=json.dumps('fake_params'),
            headers={'X-Auth-Token': 'fake_token'}
        )


@ddt.ddt
class AS13000ShareDriverTestCase(test.TestCase):
    def __init__(self, *args, **kwds):
        super(AS13000ShareDriverTestCase, self).__init__(*args, **kwds)
        self._ctxt = context.get_admin_context()
        self.configuration = FakeConfig()

    def setUp(self):
        self.mock_object(as13000_nas.CONF, '_check_required_opts')
        self.driver = as13000_nas.AS13000ShareDriver(
            configuration=self.configuration)
        super(AS13000ShareDriverTestCase, self).setUp()

    def test_do_setup(self):
        mock_login = self.mock_object(
            as13000_nas.RestAPIExecutor, 'logins', mock.Mock())
        mock_vpe = self.mock_object(
            self.driver,
            '_validate_pools_exist',
            mock.Mock())
        mock_gdd = self.mock_object(
            self.driver, '_get_directory_detail', mock.Mock(
                return_value='{}'))
        mock_gni = self.mock_object(
            self.driver, '_get_nodes_ips', mock.Mock(
                return_value=['fake_ips']))
        self.driver.do_setup(self._ctxt)
        mock_login.assert_called_once()
        mock_vpe.assert_called_once()
        mock_gdd.assert_called_once_with(
            test_config.as13000_share_pools[0])
        mock_gni.assert_called_once()

    def test_do_setup_login_fail(self):
        mock_login = self.mock_object(
            as13000_nas.RestAPIExecutor, 'logins', mock.Mock(
                side_effect=exception.ShareBackendException('fake_exception')))
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.do_setup,
            self._ctxt)
        mock_login.assert_called_once()

    def test_do_setup_vpe_failed(self):
        mock_login = self.mock_object(as13000_nas.RestAPIExecutor,
                                      'logins', mock.Mock())
        side_effect = exception.InvalidInput(reason='fake_exception')
        mock_vpe = self.mock_object(self.driver,
                                    '_validate_pools_exist',
                                    mock.Mock(side_effect=side_effect))
        self.assertRaises(exception.InvalidInput,
                          self.driver.do_setup,
                          self._ctxt)
        mock_login.assert_called_once()
        mock_vpe.assert_called_once()

    def test_check_for_setup_error_base_dir_detail_failed(self):
        self.driver.base_dir_detail = None
        self.driver.ips = ['fake_ip']
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.check_for_setup_error)

    def test_check_for_setup_error_node_status_fail(self):
        self.driver.base_dir_detail = 'fakepool'
        self.driver.ips = []
        self.assertRaises(exception.ShareBackendException,
                          self.driver.check_for_setup_error)

    @ddt.data('nfs', 'cifs')
    def test_create_share(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        mock_cd = self.mock_object(self.driver, '_create_directory',
                                   mock.Mock(return_value='/fake/path'))
        mock_cns = self.mock_object(self.driver, '_create_nfs_share')
        mock_ccs = self.mock_object(self.driver, '_create_cifs_share')
        mock_sdq = self.mock_object(self.driver, '_set_directory_quota')

        self.driver.ips = ['127.0.0.1']
        locations = self.driver.create_share(self._ctxt, share_instance)
        if share_proto == 'nfs':
            expect_locations = [{'path': r'127.0.0.1:/fake/path'}]
            self.assertEqual(locations, expect_locations)
        else:
            expect_locations = [{'path': r'\\127.0.0.1\share_fakeinstanceid'}]
            self.assertEqual(locations, expect_locations)

        mock_cd.assert_called_once_with(share_name='share_fakeinstanceid',
                                        pool_name='P')

        if share_proto == 'nfs':
            mock_cns.assert_called_once_with(share_path='/fake/path')
        elif share['share_proto'] == 'cifs':
            mock_ccs.assert_called_once_with(share_path='/fake/path',
                                             share_name='share_fakeinstanceid')

        mock_sdq.assert_called_once_with('/fake/path', share['size'])

    @ddt.data('nfs', 'cifs')
    def test_create_share_from_snapshot(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        mock_cd = self.mock_object(self.driver, '_create_directory',
                                   mock.Mock(return_value='/fake/path'))
        mock_cns = self.mock_object(self.driver, '_create_nfs_share')
        mock_ccs = self.mock_object(self.driver, '_create_cifs_share')
        mock_sdq = self.mock_object(self.driver, '_set_directory_quota')
        mock_cdtd = self.mock_object(self.driver, '_clone_directory_to_dest')

        self.driver.ips = ['127.0.0.1']
        locations = self.driver.create_share_from_snapshot(
            self._ctxt, share_instance, None)
        if share_proto == 'nfs':
            expect_locations = [{'path': r'127.0.0.1:/fake/path'}]
            self.assertEqual(locations, expect_locations)
        else:
            expect_locations = [{'path': r'\\127.0.0.1\share_fakeinstanceid'}]
            self.assertEqual(locations, expect_locations)

        mock_cd.assert_called_once_with(share_name='share_fakeinstanceid',
                                        pool_name='P')

        if share_proto == 'nfs':
            mock_cns.assert_called_once_with(share_path='/fake/path')
        elif share['share_proto'] == 'cifs':
            mock_ccs.assert_called_once_with(share_path='/fake/path',
                                             share_name='share_fakeinstanceid')

        mock_sdq.assert_called_once_with('/fake/path', share['size'])
        mock_cdtd.assert_called_once_with(snapshot=None,
                                          dest_path='/fake/path')

    @ddt.data('nfs', 'cifs')
    def test_delete_share(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        expect_share_path = r'/P/share_fakeinstanceid'

        mock_gns = self.mock_object(self.driver, '_get_nfs_share',
                                    mock.Mock(return_value=['fake_share']))
        mock_dns = self.mock_object(self.driver, '_delete_nfs_share')
        mock_gcs = self.mock_object(self.driver, '_get_cifs_share',
                                    mock.Mock(return_value=['fake_share']))
        mock_dcs = self.mock_object(self.driver, '_delete_cifs_share')
        mock_dd = self.mock_object(self.driver, '_delete_directory')

        self.driver.delete_share(self._ctxt, share_instance)
        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
            mock_dns.assert_called_once_with(expect_share_path)
        else:
            mock_gcs.assert_called_once_with('share_fakeinstanceid')
            mock_dcs.assert_called_once_with('share_fakeinstanceid')

        mock_dd.assert_called_once_with(expect_share_path)

    @ddt.data('nfs', 'cifs')
    def test_delete_share_not_exist(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        expect_share_path = r'/P/share_fakeinstanceid'

        mock_gns = self.mock_object(self.driver, '_get_nfs_share',
                                    mock.Mock(return_value=[]))
        mock_gcs = self.mock_object(self.driver, '_get_cifs_share',
                                    mock.Mock(return_value=[]))
        self.driver.delete_share(self._ctxt, share_instance)
        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
        elif share_proto == 'cifs':
            mock_gcs.assert_called_once_with('share_fakeinstanceid')

    def test_extend_share(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        expect_share_path = r'/P/share_fakeinstanceid'

        mock_sdq = self.mock_object(self.driver, '_set_directory_quota')

        self.driver.extend_share(share_instance, 2)

        mock_sdq.assert_called_once_with(expect_share_path, 2)

    @ddt.data('nfs', 'cifs')
    def test_ensure_share(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        mock_gns = self.mock_object(self.driver, '_get_nfs_share',
                                    mock.Mock(return_value=['fake_share']))
        mock_gcs = self.mock_object(self.driver, '_get_cifs_share',
                                    mock.Mock(return_value=['fake_share']))

        self.driver.ips = ['127.0.0.1']
        locations = self.driver.ensure_share(self._ctxt, share_instance)
        if share_proto == 'nfs':
            expect_locations = [{'path': r'127.0.0.1:/P/share_fakeinstanceid'}]
            self.assertEqual(locations, expect_locations)
            mock_gns.assert_called_once_with(r'/P/share_fakeinstanceid')
        else:
            expect_locations = [{'path': r'\\127.0.0.1\share_fakeinstanceid'}]
            self.assertEqual(locations, expect_locations)
            mock_gcs.assert_called_once_with(r'share_fakeinstanceid')

    def test_ensure_share_fail_1(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        self.assertRaises(exception.InvalidInput, self.driver.ensure_share,
                          self._ctxt, share_instance)

    @ddt.data('nfs', 'cifs')
    def test_ensure_share_None_share_fail(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        mock_gns = self.mock_object(self.driver, '_get_nfs_share',
                                    mock.Mock(return_value=[]))
        mock_gcs = self.mock_object(self.driver, '_get_cifs_share',
                                    mock.Mock(return_value=[]))
        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.ensure_share,
                          self._ctxt, share_instance)

        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(r'/P/share_fakeinstanceid')
        elif share['share_proto'] == 'cifs':
            mock_gcs.assert_called_once_with(r'share_fakeinstanceid')

    def test_create_snapshot(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        snapshot_instance_pseudo = {
            'share': share_instance,
            'id': 'fakesnapid'
        }

        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver.create_snapshot(self._ctxt, snapshot_instance_pseudo)

        method = 'snapshot/directory'
        request_type = 'post'
        params = {'path': r'/P/share_fakeinstanceid',
                  'snapName': 'snap_fakesnapid'}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test_delete_snapshot_normal(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        snapshot_instance_pseudo = {
            'share': share_instance,
            'id': 'fakesnapid'
        }

        mock_gsfs = self.mock_object(self.driver, '_get_snapshots_from_share',
                                     mock.Mock(return_value=['fakesnapshot']))
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver.delete_snapshot(self._ctxt, snapshot_instance_pseudo)

        mock_gsfs.assert_called_once_with('/P/share_fakeinstanceid')
        method = ('snapshot/directory?'
                  'path=/P/share_fakeinstanceid&snapName=snap_fakesnapid')
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test_delete_snapshot_not_exist(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        snapshot_instance_pseudo = {
            'share': share_instance,
            'snapshot_id': 'fakesnapid'
        }

        mock_gsfs = self.mock_object(self.driver, '_get_snapshots_from_share',
                                     mock.Mock(return_value=[]))
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver.delete_snapshot(self._ctxt, snapshot_instance_pseudo)

        mock_gsfs.assert_called_once_with('/P/share_fakeinstanceid')
        mock_rest.assert_not_called()

    @ddt.data('nfs', 'icfs', 'cifs')
    def test_transfer_rule_to_client(self, proto):
        rule = {'access_to': '1.1.1.1', 'access_level': 'rw'}

        result = self.driver.transfer_rule_to_client(proto, rule)

        client = {'name': '1.1.1.1',
                  'authority': 'rwx' if proto == 'cifs' else 'rw'}

        if proto == 'nfs':
            client.update({'type': 0})
        else:
            client.update({'type': 1})

        self.assertEqual(client, result)

    @ddt.data({'share_proto': 'nfs', 'use_access': True},
              {'share_proto': 'nfs', 'use_access': False},
              {'share_proto': 'cifs', 'use_access': True},
              {'share_proto': 'cifs', 'use_access': False})
    @ddt.unpack
    def test_update_access(self, share_proto, use_access):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        access_rules = [{'access_to': 'fakename1',
                         'access_level': 'fakelevel1'},
                        {'access_to': 'fakename2',
                         'access_level': 'fakelevel2'}]
        add_rules = [{'access_to': 'fakename1', 'access_level': 'fakelevel1'}]
        del_rules = [{'access_to': 'fakename2', 'access_level': 'fakelevel2'}]

        mock_ca = self.mock_object(self.driver, '_clear_access')

        fake_share_backend = {'pathAuthority': 'fakepathAuthority'}
        mock_gns = self.mock_object(self.driver, '_get_nfs_share',
                                    mock.Mock(return_value=fake_share_backend))
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')
        if use_access:
            self.driver.update_access(self._ctxt, share_instance,
                                      access_rules, [], [])
        else:
            self.driver.update_access(self._ctxt, share_instance,
                                      [], add_rules, del_rules)

        access_clients = [{'name': rule['access_to'],
                           'type': 0 if share_proto == 'nfs' else 1,
                           'authority': rule['access_level']
                           } for rule in access_rules]
        add_clients = [{'name': rule['access_to'],
                        'type': 0 if share_proto == 'nfs' else 1,
                        'authority': rule['access_level']
                        } for rule in add_rules]
        del_clients = [{'name': rule['access_to'],
                        'type': 0 if share_proto == 'nfs' else 1,
                        'authority': rule['access_level']
                        } for rule in del_rules]

        params = {
            'path': r'/P/share_fakeinstanceid',
            'addedClientList': [],
            'deletedClientList': [],
            'editedClientList': []
        }

        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(r'/P/share_fakeinstanceid')
            params['pathAuthority'] = fake_share_backend['pathAuthority']
        else:
            params['name'] = 'share_fakeinstanceid'

        if use_access:
            mock_ca.assert_called_once_with(share_instance)
            params['addedClientList'] = access_clients
        else:
            params['addedClientList'] = add_clients
            params['deletedClientList'] = del_clients

        mock_rest.assert_called_once_with(
            method=('file/share/%s' % share_proto),
            params=params,
            request_type='put')

    def test__update_share_stats(self):
        mock_sg = self.mock_object(FakeConfig, 'safe_get',
                                   mock.Mock(return_value='fake_as13000'))
        self.driver.pools = ['fake_pool']
        mock_gps = self.mock_object(self.driver, '_get_pool_stats',
                                    mock.Mock(return_value='fake_pool'))
        self.driver._token_time = time.time()
        mock_rt = self.mock_object(as13000_nas.RestAPIExecutor,
                                   'refresh_token')
        mock_uss = self.mock_object(driver.ShareDriver, '_update_share_stats')

        self.driver._update_share_stats()

        data = {}
        data['vendor_name'] = self.driver.VENDOR
        data['driver_version'] = self.driver.VERSION
        data['storage_protocol'] = self.driver.PROTOCOL
        data['share_backend_name'] = 'fake_as13000'
        data['snapshot_support'] = True
        data['create_share_from_snapshot_support'] = True
        data['pools'] = ['fake_pool']
        mock_sg.assert_called_once_with('share_backend_name')
        mock_gps.assert_called_once_with('fake_pool')
        mock_rt.assert_not_called()
        mock_uss.assert_called_once_with(data)

    def test__update_share_stats_refresh_token(self):
        mock_sg = self.mock_object(FakeConfig, 'safe_get',
                                   mock.Mock(return_value='fake_as13000'))
        self.driver.pools = ['fake_pool']
        mock_gps = self.mock_object(self.driver, '_get_pool_stats',
                                    mock.Mock(return_value='fake_pool'))
        self.driver._token_time = (
            time.time() - self.driver.token_available_time - 1)
        mock_rt = self.mock_object(as13000_nas.RestAPIExecutor,
                                   'refresh_token')
        mock_uss = self.mock_object(driver.ShareDriver, '_update_share_stats')

        self.driver._update_share_stats()

        data = {}
        data['vendor_name'] = self.driver.VENDOR
        data['driver_version'] = self.driver.VERSION
        data['storage_protocol'] = self.driver.PROTOCOL
        data['share_backend_name'] = 'fake_as13000'
        data['snapshot_support'] = True
        data['create_share_from_snapshot_support'] = True
        data['pools'] = ['fake_pool']
        mock_sg.assert_called_once_with('share_backend_name')
        mock_gps.assert_called_once_with('fake_pool')
        mock_rt.assert_called_once()
        mock_uss.assert_called_once_with(data)

    @ddt.data('nfs', 'cifs')
    def test__clear_access(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        fake_share_backend = {'pathAuthority': 'fakepathAuthority',
                              'clientList': ['fakeclient'],
                              'userList': ['fakeuser']}
        mock_gns = self.mock_object(self.driver, '_get_nfs_share',
                                    mock.Mock(return_value=fake_share_backend))
        mock_gcs = self.mock_object(self.driver, '_get_cifs_share',
                                    mock.Mock(return_value=fake_share_backend))
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._clear_access(share_instance)

        method = 'file/share/%s' % share_proto
        request_type = 'put'
        params = {
            'path': r'/P/share_fakeinstanceid',
            'addedClientList': [],
            'deletedClientList': [],
            'editedClientList': []
        }

        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(r'/P/share_fakeinstanceid')

            params['deletedClientList'] = fake_share_backend['clientList']
            params['pathAuthority'] = fake_share_backend['pathAuthority']
        else:
            mock_gcs.assert_called_once_with('share_fakeinstanceid')

            params['deletedClientList'] = fake_share_backend['userList']
            params['name'] = 'share_fakeinstanceid'

        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__validate_pools_exist(self):
        self.driver.pools = ['fakepool']
        mock_gdl = self.mock_object(self.driver, '_get_directory_list',
                                    mock.Mock(return_value=['fakepool']))
        self.driver._validate_pools_exist()
        mock_gdl.assert_called_once_with('/')

    def test__validate_pools_exist_fail(self):
        self.driver.pools = ['fakepool_fail']
        mock_gdl = self.mock_object(self.driver, '_get_directory_list',
                                    mock.Mock(return_value=['fakepool']))
        self.assertRaises(exception.InvalidInput,
                          self.driver._validate_pools_exist)
        mock_gdl.assert_called_once_with('/')

    @ddt.data(0, 1)
    def test__get_directory_quota(self, hardunit):
        fake_data = {'hardthreshold': 200,
                     'hardunit': hardunit,
                     'capacity': '50GB'}
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=fake_data))

        total, used = (self.driver._get_directory_quota('fakepath'))

        if hardunit == 0:
            self.assertEqual((200, 50), (total, used))
        else:
            self.assertEqual((200 * 1024, 50), (total, used))
        method = 'file/quota/directory?path=/fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__get_directory_quota_fail(self):
        fake_data = {'hardthreshold': None,
                     'hardunit': 0,
                     'capacity': '50GB'}
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=fake_data))

        self.assertRaises(exception.ShareBackendException,
                          self.driver._get_directory_quota, 'fakepath')
        method = 'file/quota/directory?path=/fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__get_pool_stats(self):
        mock_gdq = self.mock_object(self.driver, '_get_directory_quota',
                                    mock.Mock(return_value=(200, 50)))
        pool = dict()
        pool['pool_name'] = 'fakepath'
        pool['reserved_percentage'] = 0
        pool['reserved_snapshot_percentage'] = 0
        pool['reserved_share_extend_percentage'] = 0
        pool['max_over_subscription_ratio'] = 20.0
        pool['dedupe'] = False
        pool['compression'] = False
        pool['qos'] = False
        pool['thin_provisioning'] = True
        pool['total_capacity_gb'] = 200
        pool['free_capacity_gb'] = 150
        pool['allocated_capacity_gb'] = 50
        pool['snapshot_support'] = True
        pool['create_share_from_snapshot_support'] = True

        result = self.driver._get_pool_stats('fakepath')
        self.assertEqual(pool, result)
        mock_gdq.assert_called_once_with('fakepath')

    def test__get_directory_list(self):
        fake_dir_list = [{'name': 'fakedirectory1', 'size': 20},
                         {'name': 'fakedirectory2', 'size': 30}]
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=fake_dir_list))

        expected = ['fakedirectory1', 'fakedirectory2']
        result = self.driver._get_directory_list('/fakepath')
        self.assertEqual(expected, result)
        method = 'file/directory?path=/fakepath'
        mock_rest.assert_called_once_with(method=method,
                                          request_type='get')

    def test__create_directory(self):
        base_dir_detail = {
            'path': '/fakepath',
            'authorityInfo': {'user': 'root',
                              'group': 'root',
                              'authority': 'rwxrwxrwx'
                              },
            'dataProtection': {'type': 0,
                               'dc': 2,
                               'cc': 1,
                               'rn': 0,
                               'st': 4},
            'poolName': 'storage_pool'
        }
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver.base_dir_detail = base_dir_detail
        result = self.driver._create_directory('fakename', 'fakepool')

        self.assertEqual('/fakepool/fakename', result)

        method = 'file/directory'
        request_type = 'post'
        params = {'name': 'fakename',
                  'parentPath': base_dir_detail['path'],
                  'authorityInfo': base_dir_detail['authorityInfo'],
                  'dataProtection': base_dir_detail['dataProtection'],
                  'poolName': base_dir_detail['poolName']}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__delete_directory(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._delete_directory('/fakepath')

        method = 'file/directory?path=/fakepath'
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__set_directory_quota(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._set_directory_quota('fakepath', 200)

        method = 'file/quota/directory'
        request_type = 'put'
        params = {'path': 'fakepath',
                  'hardthreshold': 200,
                  'hardunit': 2}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__create_nfs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._create_nfs_share('fakepath')

        method = 'file/share/nfs'
        request_type = 'post'
        params = {'path': 'fakepath', 'pathAuthority': 'rw', 'client': []}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__delete_nfs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._delete_nfs_share('/fakepath')

        method = 'file/share/nfs?path=/fakepath'
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__get_nfs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value='fakebackend'))

        result = self.driver._get_nfs_share('/fakepath')
        self.assertEqual('fakebackend', result)

        method = 'file/share/nfs?path=/fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__create_cifs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._create_cifs_share('fakename', 'fakepath')

        method = 'file/share/cifs'
        request_type = 'post'
        params = {'path': 'fakepath', 'name': 'fakename', 'userlist': []}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__delete_cifs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._delete_cifs_share('fakename')

        method = 'file/share/cifs?name=fakename'
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__get_cifs_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value='fakebackend'))

        result = self.driver._get_cifs_share('fakename')
        self.assertEqual('fakebackend', result)

        method = 'file/share/cifs?name=fakename'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test__clone_directory_to_dest(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")
        snapshot_instance_pseudo = {
            'id': 'fakesnapid',
            'share_instance': share_instance
        }

        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api')

        self.driver._clone_directory_to_dest(snapshot_instance_pseudo,
                                             'fakepath')

        method = 'snapshot/directory/clone'
        request_type = 'post'
        params = {'path': '/P/share_fakeinstanceid',
                  'snapName': 'snap_fakesnapid',
                  'destPath': 'fakepath'}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test__get_snapshots_from_share(self):
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=['fakesnap']))

        result = self.driver._get_snapshots_from_share('/fakepath')

        self.assertEqual(['fakesnap'], result)
        method = 'snapshot/directory?path=/fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    @ddt.data('nfs', 'cifs')
    def test__get_location_path(self, proto):
        self.driver.ips = ['ip1', 'ip2']

        result = self.driver._get_location_path('fake_name',
                                                '/fake/path',
                                                proto)
        if proto == 'nfs':
            expect = [{'path': 'ip1:/fake/path'},
                      {'path': 'ip2:/fake/path'}]
        else:
            expect = [{'path': r'\\ip1\fake_name'},
                      {'path': r'\\ip2\fake_name'}]
        self.assertEqual(expect, result)

    def test__get_nodes_virtual_ips(self):
        ctdb_set = {
            'virtualIpList': [{'ip': 'fakeip1/24'},
                              {'ip': 'fakeip2/24'}]
        }

        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=ctdb_set))

        result = self.driver._get_nodes_virtual_ips()
        self.assertEqual(result, ['fakeip1', 'fakeip2'])
        mock_rest.assert_called_once_with(method='ctdb/set',
                                          request_type='get')

    def test__get_nodes_physical_ips(self):
        nodes = [{'nodeIp': 'fakeip1', 'runningStatus': 1, 'healthStatus': 1},
                 {'nodeIp': 'fakeip2', 'runningStatus': 1, 'healthStatus': 0},
                 {'nodeIp': 'fakeip3', 'runningStatus': 0, 'healthStatus': 1},
                 {'nodeIp': 'fakeip4', 'runningStatus': 0, 'healthStatus': 0}]
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=nodes))

        result = self.driver._get_nodes_physical_ips()

        expect = ['fakeip1']
        self.assertEqual(expect, result)
        mock_rest.assert_called_once_with(method='cluster/node/cache',
                                          request_type='get')

    def test__get_nodes_ips(self):
        mock_virtual = self.mock_object(self.driver, '_get_nodes_virtual_ips',
                                        mock.Mock(return_value=['ip1']))
        mock_physical = self.mock_object(self.driver,
                                         '_get_nodes_physical_ips',
                                         mock.Mock(return_value=['ip2']))

        result = self.driver._get_nodes_ips()
        self.assertEqual(['ip1', 'ip2'], result)
        mock_virtual.assert_called_once()
        mock_physical.assert_called_once()

    @ddt.data('nfs', 'cifs')
    def test__get_share_instance_pnsp(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto)
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        result = self.driver._get_share_instance_pnsp(share_instance)

        self.assertEqual(('P', 'share_fakeinstanceid', 1, share_proto), result)

    @ddt.data('5000000000', '5000000k', '5000mb', '50G', '5TB')
    def test__unit_convert(self, capacity):
        trans = {'5000000000': '%.0f' % (float(5000000000) / 1024 ** 3),
                 '5000000k': '%.0f' % (float(5000000) / 1024 ** 2),
                 '5000mb': '%.0f' % (float(5000) / 1024),
                 '50G': '%.0f' % float(50),
                 '5TB': '%.0f' % (float(5) * 1024)}
        expect = float(trans[capacity])
        result = self.driver._unit_convert(capacity)
        self.assertEqual(expect, result)

    def test__format_name(self):
        a = 'atest-1234567890-1234567890-1234567890'
        expect = 'atest_1234567890_1234567890_1234'
        result = self.driver._format_name(a)
        self.assertEqual(expect, result)

    def test__generate_share_name(self):
        share = fake_share.fake_share()
        share_instance = fake_share.fake_share_instance(share, host="H@B#P")

        result = self.driver._generate_share_name(share_instance)

        self.assertEqual('share_fakeinstanceid', result)

    def test__generate_snapshot_name(self):
        snapshot_instance_pesudo = {'id': 'fakesnapinstanceid'}

        result = self.driver._generate_snapshot_name(snapshot_instance_pesudo)

        self.assertEqual('snap_fakesnapinstanceid', result)

    def test__generate_share_path(self):
        result = self.driver._generate_share_path('fakepool', 'fakename')

        self.assertEqual('/fakepool/fakename', result)

    def test__get_directory_detail(self):
        details = [{'poolName': 'fakepool1'},
                   {'poolName': 'fakepool2'}]
        mock_rest = self.mock_object(as13000_nas.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=details))

        result = self.driver._get_directory_detail('fakepath')

        self.assertEqual(details[0], result)
        method = 'file/directory/detail?path=/fakepath'
        request_type = 'get'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)
