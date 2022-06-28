# Copyright (c) 2021 Zadara Storage, Inc.
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
Tests for Zadara VPSA Share driver
"""

import copy
import requests

from unittest import mock
from urllib import parse

from manila import context
from manila import exception as manila_exception
from manila.share import configuration
from manila.share.drivers.zadara import zadara
from manila import test
from manila.tests import fake_share


def check_access_key(func):
    """A decorator for all operations that needed an API before executing"""
    def wrap(self, *args, **kwargs):
        if not self._is_correct_access_key():
            return RUNTIME_VARS['bad_login']
        return func(self, *args, **kwargs)

    return wrap


DEFAULT_RUNTIME_VARS = {
    'status': 200,
    'user': 'test',
    'password': 'test_password',
    'access_key': '0123456789ABCDEF',
    'volumes': [],
    'servers': [],
    'controllers': [('active_ctrl', {'display-name': 'test_ctrl'})],
    'counter': 1000,

    "login": """
        {
         "response": {
                      "user": {
                               "updated-at": "2021-01-22",
                               "access-key": "%s",
                               "id": 1,
                               "created-at": "2021-01-22",
                               "email": "jsmith@example.com",
                               "username": "jsmith"
                              },
                      "status": 0
                     }
        }""",
    "good": """
         {
          "response": {
                       "status": 0
                      }
         }""",
    "good_snapshot": """
         {
          "response": {
                       "snapshot_name": "fakesnaplocation",
                       "status": 0
                      }
         }""",
    "bad_login": """
        {
         "response": {
                      "status": 5,
                      "status-msg": "Some message..."
                     }
        }""",
    "bad_volume": """
        {
         "response": {
                      "status": 10081,
                      "status-msg": "Virtual volume xxx should be found"
                     }
        }""",
    "fake_volume": """
        {
         "response": {
                      "volumes": [],
                      "status": 0,
                      "status-msg": "Virtual volume xxx doesn't exist"
                     }
        }""",
    "bad_server": """
        {
         "response": {
                      "status": 10086,
                      "status-msg": "Server xxx not found"
                     }
        }""",
    "server_created": """
        {
         "response": {
                      "server_name": "%s",
                      "status": 0
                     }
        }""",
}

RUNTIME_VARS = None


class FakeResponse(object):
    def __init__(self, method, url, params, body, headers, **kwargs):
        # kwargs include: verify, timeout
        self.method = method
        self.url = url
        self.body = body
        self.params = params
        self.headers = headers
        self.status = RUNTIME_VARS['status']

    @property
    def access_key(self):
        """Returns Response Access Key"""
        return self.headers["X-Access-Key"]

    def read(self):
        ops = {'POST': [('/api/users/login.json', self._login),
                        ('/api/volumes.json', self._create_volume),
                        ('/api/servers.json', self._create_server),
                        ('/api/servers/*/volumes.json', self._attach),
                        ('/api/volumes/*/rename.json', self._rename),
                        ('/api/volumes/*/detach.json', self._detach),
                        ('/api/volumes/*/expand.json', self._expand),
                        ('/api/consistency_groups/*/snapshots.json',
                            self._create_snapshot),
                        ('/api/snapshots/*/rename.json',
                            self._rename_snapshot),
                        ('/api/consistency_groups/*/clone.json',
                            self._create_clone_from_snapshot),
                        ('/api/consistency_groups/*/clone.json',
                            self._create_clone)],
               'DELETE': [('/api/volumes/*', self._delete),
                          ('/api/snapshots/*', self._delete_snapshot)],
               'GET': [('/api/volumes.json?showonlyfile=YES',
                        self._list_volumes),
                       ('/api/volumes.json?display_name=*',
                           self._get_volume_by_name),
                       ('/api/pools/*.json', self._get_pool),
                       ('/api/vcontrollers.json', self._list_controllers),
                       ('/api/servers.json', self._list_servers),
                       ('/api/consistency_groups/*/snapshots.json',
                           self._list_vol_snapshots),
                       ('/api/volumes/*/servers.json',
                           self._list_vol_attachments)]
               }

        ops_list = ops[self.method]
        for (templ_url, func) in ops_list:
            if self._compare_url(self.url, templ_url):
                result = func()
                return result

    @staticmethod
    def _compare_url(url, template_url):
        items = url.split('/')
        titems = template_url.split('/')
        for (i, titem) in enumerate(titems):
            if '*' not in titem and titem != items[i]:
                return False
            if '?' in titem and titem.split('=')[0] != items[i].split('=')[0]:
                return False

        return True

    @staticmethod
    def _get_counter():
        cnt = RUNTIME_VARS['counter']
        RUNTIME_VARS['counter'] += 1
        return cnt

    def _login(self):
        params = self.body
        if (params['user'] == RUNTIME_VARS['user'] and
                params['password'] == RUNTIME_VARS['password']):
            return RUNTIME_VARS['login'] % RUNTIME_VARS['access_key']
        else:
            return RUNTIME_VARS['bad_login']

    def _is_correct_access_key(self):
        return self.access_key == RUNTIME_VARS['access_key']

    @check_access_key
    def _create_volume(self):
        params = self.body
        params['display-name'] = params['name']
        params['cg-name'] = params['name']
        params['snapshots'] = []
        params['server_ext_names'] = ''
        params['provisioned-capacity'] = 1
        vpsa_vol = 'volume-%07d' % self._get_counter()
        params['nfs-export-path'] = '10.2.1.56:/export/%s' % vpsa_vol
        RUNTIME_VARS['volumes'].append((vpsa_vol, params))
        return RUNTIME_VARS['good']

    @check_access_key
    def _create_server(self):
        params = self.body

        params['display-name'] = params['display_name']
        vpsa_srv = 'srv-%07d' % self._get_counter()
        RUNTIME_VARS['servers'].append((vpsa_srv, params))
        return RUNTIME_VARS['server_created'] % vpsa_srv

    @check_access_key
    def _attach(self):
        srv = self.url.split('/')[3]

        params = self.body

        vol = params['volume_name[]']

        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['name'] == vol:
                attachments = params['server_ext_names'].split(',')
                if srv in attachments:
                    # already attached - ok
                    return RUNTIME_VARS['good']
                else:
                    if not attachments[0]:
                        params['server_ext_names'] = srv
                    else:
                        params['server_ext_names'] += ',' + srv
                    return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _detach(self):
        params = self.body
        vol = self.url.split('/')[3]
        srv = params['server_name[]']

        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['name'] == vol:
                attachments = params['server_ext_names'].split(',')
                if srv not in attachments:
                    return RUNTIME_VARS['bad_server']
                else:
                    attachments.remove(srv)
                    params['server_ext_names'] = (','.join([str(elem)
                                                  for elem in attachments]))
                    return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _expand(self):
        params = self.body
        vol = self.url.split('/')[3]
        capacity = params['capacity']

        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['name'] == vol:
                params['capacity'] = capacity
                return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _rename(self):
        params = self.body
        vol = self.url.split('/')[3]

        for (vol_name, vol_params) in RUNTIME_VARS['volumes']:
            if vol_params['name'] == vol:
                vol_params['name'] = params['new_name']
                vol_params['display-name'] = params['new_name']
                vol_params['cg-name'] = params['new_name']
                return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _rename_snapshot(self):
        params = self.body
        vpsa_snapshot = self.url.split('/')[3]

        for (vol_name, vol_params) in RUNTIME_VARS['volumes']:
            for snapshot in vol_params['snapshots']:
                if vpsa_snapshot == snapshot['provider-location']:
                    snapshot['name'] = params['newname']
                    snapshot['display-name'] = params['newname']
                    return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _create_snapshot(self):
        params = self.body
        cg_name = self.url.split('/')[3]
        snap_name = params['display_name']

        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['cg-name'] == cg_name:
                snapshots = params['snapshots']
                if snap_name in snapshots:
                    # already attached
                    return RUNTIME_VARS['bad_volume']
                else:
                    snapshots.append(snap_name)
                    return RUNTIME_VARS['good_snapshot']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _delete_snapshot(self):
        snap = self.url.split('/')[3].split('.')[0]

        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if snap in params['snapshots']:
                params['snapshots'].remove(snap)
                return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    @check_access_key
    def _create_clone_from_snapshot(self):
        params = self.body
        params['display-name'] = params['name']
        params['cg-name'] = params['name']
        params['capacity'] = 1
        params['snapshots'] = []
        params['server_ext_names'] = ''
        params['pool'] = 'pool-0001'
        params['provisioned-capacity'] = 1
        vpsa_vol = 'volume-%07d' % self._get_counter()
        params['nfs-export-path'] = '10.2.1.56:/export/%s' % vpsa_vol
        RUNTIME_VARS['volumes'].append((vpsa_vol, params))
        return RUNTIME_VARS['good']

    @check_access_key
    def _create_clone(self):
        params = self.body
        params['display-name'] = params['name']
        params['cg-name'] = params['name']
        params['capacity'] = 1
        params['snapshots'] = []
        params['server_ext_names'] = ''
        vpsa_vol = 'volume-%07d' % self._get_counter()
        RUNTIME_VARS['volumes'].append((vpsa_vol, params))
        return RUNTIME_VARS['good']

    def _delete(self):
        vol = self.url.split('/')[3].split('.')[0]

        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['name'] == vol:
                if params['server_ext_names']:
                    # there are attachments - should be volume busy error
                    return RUNTIME_VARS['bad_volume']
                else:
                    RUNTIME_VARS['volumes'].remove((vol_name, params))
                    return RUNTIME_VARS['good']

        return RUNTIME_VARS['bad_volume']

    def _generate_list_resp(self, null_body, body, lst, vol):
        resp = ''
        for (obj, params) in lst:
            if vol:
                resp += body % (params['name'],
                                params['display-name'],
                                params['cg-name'],
                                params['capacity'],
                                params['pool'],
                                params['provisioned-capacity'],
                                params['nfs-export-path'])
            else:
                resp += body % (obj, params['display-name'])
        if resp:
            return resp
        else:
            return null_body

    def _list_volumes(self):
        null_body = """
        {
         "response": {
                      "volumes": [
                                 ],
                      "status": 0
                     }
        }"""
        body = """
        {
         "response": {
                      "volumes": %s,
                      "status": 0
                     }
        }"""

        volume_obj = """
                     {
                      "name": "%s",
                      "display_name": "%s",
                      "cg_name": "%s",
                      "status": "Available",
                      "virtual_capacity": %d,
                      "pool_name": "%s",
                      "allocated-capacity": 1,
                      "provisioned_capacity": "%s",
                      "raid-group-name": "r5",
                      "cache": "write-through",
                      "created-at": "2021-01-22",
                      "modified-at": "2021-01-22",
                      "nfs_export_path": "%s"
                     }
                     """
        if len(RUNTIME_VARS['volumes']) == 0:
            return null_body
        resp = ''
        volume_list = ''
        count = 0
        for (vol_name, params) in RUNTIME_VARS['volumes']:
            volume_dict = volume_obj % (params['name'],
                                        params['display-name'],
                                        params['cg-name'],
                                        params['capacity'],
                                        params['pool'],
                                        params['provisioned-capacity'],
                                        params['nfs-export-path'])
            if count == 0:
                volume_list += volume_dict
                count += 1
            elif count != len(RUNTIME_VARS['volumes']):
                volume_list = volume_list + ',' + volume_dict
                count += 1
        if volume_list:
            volume_list = '[' + volume_list + ']'
            resp = body % volume_list
            return resp

        return RUNTIME_VARS['bad_volume']

    def _get_volume_by_name(self):
        volume_name = self.url.split('=')[1]
        body = """
        {
         "response": {
                      "volumes": [
                                  {
                                   "name": "%s",
                                   "display_name": "%s",
                                   "cg_name": "%s",
                                   "status": "Available",
                                   "virtual_capacity": %d,
                                   "pool_name": "%s",
                                   "allocated-capacity": 1,
                                   "provisioned_capacity": %d,
                                   "raid-group-name": "r5",
                                   "cache": "write-through",
                                   "created-at": "2021-01-22",
                                   "modified-at": "2021-01-22",
                                   "nfs_export_path": "%s",
                                   "server_ext_names": "%s"
                                  }
                                 ],
                      "status": 0
                     }
        }"""
        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['name'] == volume_name:
                resp = body % (volume_name, params['display-name'],
                               params['cg-name'], params['capacity'],
                               params['pool'], params['provisioned-capacity'],
                               params['nfs-export-path'],
                               params['server_ext_names'])
                return resp

        return RUNTIME_VARS['fake_volume']

    def _list_controllers(self):
        null_body = """
        {
         "response": {
                      "vcontrollers": [
                                      ],
                      "status": 0
                     }
        }"""
        body = """
        {
         "response": {
                      "vcontrollers": [
                                       {
                                        "name": "%s",
                                        "display_name": "%s",
                                        "state": "active",
                                        "target":
                                        "iqn.2011-04.zadarastorage:vsa-xxx:1",
                                        "iscsi_ip": "1.1.1.1",
                                        "iscsi_ipv6": "",
                                        "mgmt-ip": "1.1.1.1",
                                        "software-ver": "0.0.09-05.1--77.7",
                                        "heartbeat1": "ok",
                                        "heartbeat2": "ok",
                                        "vpsa_chap_user": "test_chap_user",
                                        "vpsa_chap_secret": "test_chap_secret"
                                  }
                                 ],
                      "status": 0
                     }
        }"""
        return self._generate_list_resp(null_body,
                                        body,
                                        RUNTIME_VARS['controllers'],
                                        False)

    def _get_pool(self):
        response = """
        {
         "response": {
                      "pool": {
                               "name": "pool-0001",
                               "capacity": 100,
                               "available_capacity": 99,
                               "provisioned_capacity": 1
                              },
                      "status": 0
                     }
        }"""
        return response

    def _list_servers(self):
        null_body = """
        {
         "response": {
                      "servers": [
                                 ],
                      "status": 0
                     }
        }"""
        body = """
        {
         "response": {
                      "servers": %s,
                      "status": 0
                     }
        }"""

        server_obj = """
                     {
                      "name": "%s",
                      "display_name": "%s",
                      "iscsi_ip": "%s",
                      "status": "Active",
                      "created-at": "2021-01-22",
                      "modified-at": "2021-01-22"
                     }
                     """
        resp = ''
        server_list = ''
        count = 0
        for (obj, params) in RUNTIME_VARS['servers']:
            server_dict = server_obj % (obj,
                                        params['display-name'],
                                        params['iqn'])
            if count == 0:
                server_list += server_dict
                count += 1
            elif count != len(RUNTIME_VARS['servers']):
                server_list = server_list + ',' + server_dict
                count += 1
        server_list = '[' + server_list + ']'
        resp = body % server_list
        if resp:
            return resp
        else:
            return null_body

    def _get_server_obj(self, name):
        for (srv_name, params) in RUNTIME_VARS['servers']:
            if srv_name == name:
                return params

    def _list_vol_attachments(self):
        vol = self.url.split('/')[3]
        null_body = """
        {
         "response": {
                      "servers": [
                                 ],
                      "status": 0
                     }
        }"""
        body = """
        {
         "response": {
                      "servers": %s,
                      "status": 0
                     }
        }"""

        server_obj = """
                     {
                      "name": "%s",
                      "display_name": "%s",
                      "iscsi_ip": "%s",
                      "target":
                      "iqn.2011-04.zadarastorage:vsa-xxx:1",
                      "lun": 0
                     }
                     """
        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['name'] == vol:
                attachments = params['server_ext_names'].split(',')
                if not attachments[0]:
                    return null_body
                resp = ''
                server_list = ''
                count = 0
                for server in attachments:
                    srv_params = self._get_server_obj(server)
                    server_dict = (server_obj % (server,
                                   srv_params['display_name'],
                                   srv_params['iscsi']))
                    if count == 0:
                        server_list += server_dict
                        count += 1
                    elif count != len(attachments):
                        server_list = server_list + ',' + server_dict
                        count += 1
                server_list = '[' + server_list + ']'
                resp = body % server_list
                return resp

        return RUNTIME_VARS['bad_volume']

    def _list_vol_snapshots(self):
        cg_name = self.url.split('/')[3]

        null_body = """
        {
         "response": {
                      "snapshots": [
                                   ],
                      "status": 0
                     }
        }"""

        body = """
        {
         "response": {
                      "snapshots": %s,
                      "status": 0
                     }
        }"""

        snapshot_obj = """
                       {
                        "name": "%s",
                        "display_name": "%s",
                        "status": "normal",
                        "cg-name": "%s",
                        "pool-name": "pool-00000001"
                       }
                       """
        for (vol_name, params) in RUNTIME_VARS['volumes']:
            if params['cg-name'] == cg_name:
                snapshots = params['snapshots']
                if len(snapshots) == 0:
                    return null_body
                resp = ''
                snapshot_list = ''
                count = 0

                for snapshot in snapshots:
                    snapshot_dict = snapshot_obj % (snapshot, snapshot,
                                                    cg_name)
                    if count == 0:
                        snapshot_list += snapshot_dict
                        count += 1
                    elif count != len(snapshots):
                        snapshot_list = snapshot_list + ',' + snapshot_dict
                        count += 1
                snapshot_list = '[' + snapshot_list + ']'
                resp = body % snapshot_list
                return resp

        return RUNTIME_VARS['bad_volume']


class FakeRequests(object):
    """A fake requests for zadara volume driver tests."""
    def __init__(self, method, api_url, params=None, data=None,
                 headers=None, **kwargs):
        apiurl_items = parse.urlparse(api_url)
        if apiurl_items.query:
            url = apiurl_items.path + '?' + apiurl_items.query
        else:
            url = apiurl_items.path
        res = FakeResponse(method, url, params, data, headers, **kwargs)
        self.content = res.read()
        self.status_code = res.status


class ZadaraVPSAShareDriverTestCase(test.TestCase):

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def setUp(self):
        super(ZadaraVPSAShareDriverTestCase, self).setUp()

        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self._context = context.get_admin_context()
        self.configuration = mock.Mock(spec=configuration.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)

        global RUNTIME_VARS
        RUNTIME_VARS = copy.deepcopy(DEFAULT_RUNTIME_VARS)

        self.configuration.driver_handles_share_servers = False
        self.configuration.network_config_group = (
            'fake_network_config_group')
        self.configuration.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.configuration.reserved_percentage = 0
        self.configuration.reserved_snapshot_percentage = 0
        self.configuration.reserved_share_extend_percentage = 0
        self.configuration.zadara_use_iser = True
        self.configuration.zadara_vpsa_host = '192.168.5.5'
        self.configuration.zadara_vpsa_port = '80'
        self.configuration.zadara_user = 'test'
        self.configuration.zadara_password = 'test_password'
        self.configuration.zadara_access_key = '0123456789ABCDEF'
        self.configuration.zadara_vpsa_poolname = 'pool-0001'
        self.configuration.zadara_vol_encrypt = False
        self.configuration.zadara_share_name_template = 'OS_share-%s'
        self.configuration.zadara_share_snap_name_template = (
            'OS_share-snapshot-%s')
        self.configuration.zadara_vpsa_use_ssl = False
        self.configuration.zadara_ssl_cert_verify = False
        self.configuration.zadara_default_snap_policy = False
        self.configuration.zadara_driver_ssl_cert_path = None
        self.configuration.zadara_gen3_vol_compress = True
        self.configuration.zadara_gen3_vol_dedupe = True
        self.configuration.share_backend_name = 'zadaravpsa'
        self.configuration.reserved_share_percentage = '0'
        self.configuration.reserved_share_from_snapshot_percentage = '0'
        self.configuration.reserved_share_extend_percentage = 0
        self.configuration.replication_domain = None
        self.configuration.filter_function = None
        self.configuration.goodness_function = None
        self.configuration.goodness_function = None
        self.driver = (zadara.ZadaraVPSAShareDriver(
                       configuration=self.configuration))
        self.driver.do_setup(None)
        self.driver.api.get_share_metadata = mock.Mock(return_value={})
        self.driver._get_share_export_location = mock.Mock()

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_do_setup(self):
        self.driver.do_setup(self._context)
        self.assertIsNotNone(self.driver.vpsa)
        self.assertEqual(self.driver.vpsa.access_key,
                         self.configuration.zadara_access_key)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_no_active_ctrl(self):
        share = fake_share.fake_share(id='fakeid', share_proto='NFS',
                                      share_id='fakeshareid')
        self.driver.create_share(self._context, share)
        access = fake_share.fake_access()

        RUNTIME_VARS['controllers'] = []
        self.assertRaises(manila_exception.ZadaraVPSANoActiveController,
                          self.driver._allow_access,
                          self._context,
                          share, access)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_create_share_unsupported_proto(self):
        share = fake_share.fake_share(share_proto='INVALID')
        self.assertRaises(manila_exception.ZadaraInvalidProtocol,
                          self.driver.create_share,
                          self._context,
                          share)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_create_delete_share(self):
        """Create share."""
        share = fake_share.fake_share(share_proto='NFS',
                                      share_id='fakeshareid')
        self.driver.create_share(self._context, share)
        self.driver.delete_share(self._context, share)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_create_delete_multiple_shares(self):
        """Create/Delete multiple shares."""
        share1 = fake_share.fake_share(id='fakeid1', share_proto='NFS',
                                       share_id='fakeshareid1')
        self.driver.create_share(self._context, share1)

        share2 = fake_share.fake_share(id='fakeid2', share_proto='CIFS',
                                       share_id='fakeshareid2')
        self.driver.create_share(self._context, share2)

        self.driver.delete_share(self._context, share1)
        self.driver.delete_share(self._context, share2)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_delete_non_existent(self):
        """Delete non-existent share."""
        share = fake_share.fake_share(share_proto='NFS',
                                      share_id='fakeshareid')
        self.driver.delete_share(self._context, share)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_create_delete_share_snapshot(self):
        """Create/Delete share snapshot."""
        share1 = fake_share.fake_share(id='fakeid1', share_proto='NFS',
                                       share_id='fakeshareid1')
        self.driver.create_share(self._context, share1)
        snapshot = fake_share.fake_snapshot(name='fakesnap',
                                            share=share1,
                                            share_name=share1['name'],
                                            share_id=share1['id'],
                                            provider_location='fakelocation')

        share2 = fake_share.fake_share(id='fakeid2', share_proto='NFS',
                                       share_id='fakeshareid2')
        self.assertRaises(manila_exception.ManilaException,
                          self.driver.create_snapshot,
                          self._context,
                          {'name': snapshot['name'],
                           'id': snapshot['id'],
                           'share': share2})

        self.driver.create_snapshot(self._context, snapshot)

        # Deleted should succeed for missing volume
        self.driver.delete_snapshot(self._context,
                                    {'name': snapshot['name'],
                                     'id': snapshot['id'],
                                     'share': share2})
        # Deleted should succeed for missing snap
        self.driver.delete_snapshot(self._context,
                                    {'name': 'wrong_snap',
                                     'id': 'wrong_id',
                                     'share': share1})

        self.driver.delete_snapshot(self._context, snapshot)
        self.driver.delete_share(self._context, share1)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_extend_share(self):
        """Expand share test."""
        share1 = fake_share.fake_share(id='fakeid1', share_proto='NFS',
                                       share_id='fakeshareid', size=10)
        share2 = fake_share.fake_share(id='fakeid2',
                                       share_proto='NFS', size=10)
        self.driver.create_share(self._context, share1)

        self.assertRaises(manila_exception.ZadaraShareNotFound,
                          self.driver.extend_share,
                          share2, 15)

        self.driver.extend_share(share1, 15)
        self.driver.delete_share(self._context, share1)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_create_share_from_snapshot(self):
        """Create a share from snapshot test."""
        share1 = fake_share.fake_share(id='fakeid1', share_proto='NFS',
                                       share_id='fakeshareid1')
        share2 = fake_share.fake_share(id='fakeid2', share_proto='NFS',
                                       share_id='fakeshareid2')
        self.driver.create_share(self._context, share1)

        snapshot = fake_share.fake_snapshot(name='fakesnap',
                                            share=share1,
                                            share_name=share1['name'],
                                            share_id=share1['id'],
                                            share_instance_id=share1['id'],
                                            provider_location='fakelocation')
        self.driver.create_snapshot(self._context, snapshot)

        self.assertRaises(manila_exception.ManilaException,
                          self.driver.create_share_from_snapshot,
                          self._context,
                          share2,
                          {'name': snapshot['name'],
                           'id': snapshot['id'],
                           'share': share2,
                           'share_instance_id': share2['id']})

        self.assertRaises(manila_exception.ManilaException,
                          self.driver.create_share_from_snapshot,
                          self._context,
                          share2,
                          {'name': 'fakesnapname',
                           'id': 'fakesnapid',
                           'share': share1,
                           'share_instance_id': share1['id']})

        self.driver.create_share_from_snapshot(self._context, share2, snapshot)
        self.driver.delete_share(self._context, share1)
        self.driver.delete_share(self._context, share2)

    def create_vpsa_backend_share(self):
        vpsashare_params = {}
        vpsashare_params['id'] = 'fake_id'
        vpsashare_params['name'] = 'fake_name'
        vpsashare_params['display-name'] = 'fake_name'
        vpsashare_params['cg-name'] = 'fake_name'
        vpsashare_params['size'] = 1
        vpsashare_params['capacity'] = 1
        vpsashare_params['pool'] = 'pool-0001'
        vpsashare_params['share_proto'] = 'NFS'
        vpsashare_params['nfs-export-path'] = '10.2.1.56:/export/manage_id'
        vpsashare_params['provisioned-capacity'] = 1
        vpsashare_params['server_ext_names'] = ''
        vpsa_volname = 'fake-volume'
        vpsa_share = (vpsa_volname, vpsashare_params)
        RUNTIME_VARS['volumes'].append(vpsa_share)
        return vpsa_share

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_manage_existing_share(self):
        share1 = {'id': 'manage_name',
                  'name': 'manage_name',
                  'display-name': 'manage_name',
                  'size': 1,
                  'share_proto': 'NFS',
                  'export_locations':
                  [{'path': '10.2.1.56:/export/manage_id'}]}
        driver_options = {}
        vpsa_share = self.create_vpsa_backend_share()

        self.driver.manage_existing(share1, driver_options)
        self.assertEqual(vpsa_share[1]['display-name'].split('-')[1],
                         share1['display-name'])
        self.driver.delete_share(self._context, share1)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_get_share_stats(self):
        """Get stats test."""
        self.configuration.safe_get.return_value = 'ZadaraVPSAShareDriver'
        data = self.driver.get_share_stats(True)
        self.assertEqual('Zadara Storage', data['vendor_name'])
        self.assertEqual('unknown', data['total_capacity_gb'])
        self.assertEqual('unknown', data['free_capacity_gb'])
        self.assertEqual(data['reserved_percentage'],
                         self.configuration.reserved_percentage)
        self.assertEqual(data['reserved_snapshot_percentage'],
                         self.configuration.reserved_snapshot_percentage)
        self.assertEqual(data['reserved_share_extend_percentage'],
                         self.configuration.reserved_share_extend_percentage)
        self.assertEqual(data['snapshot_support'], True)
        self.assertEqual(data['create_share_from_snapshot_support'], True)
        self.assertEqual(data['revert_to_snapshot_support'], False)
        self.assertEqual(data['vendor_name'], 'Zadara Storage')
        self.assertEqual(data['driver_version'], self.driver.VERSION)
        self.assertEqual(data['storage_protocol'], 'NFS_CIFS')
        self.assertEqual(data['share_backend_name'],
                         self.configuration.share_backend_name)

    def test_allow_access_with_incorrect_access_type(self):
        share = fake_share.fake_share(id='fakeid1', share_proto='NFS')
        access = fake_share.fake_access(access_type='fake_type')

        self.assertRaises(manila_exception.ZadaraInvalidShareAccessType,
                          self.driver._allow_access,
                          self._context, share, access)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_share_allow_deny_access(self):
        """Test share access allow any deny rules."""
        share = fake_share.fake_share(id='fakeid', share_proto='NFS',
                                      share_id='fakeshareid')
        self.driver.create_share(self._context, share)
        access = fake_share.fake_access()

        # Attach server for accessing share with the fake access rules
        allow_access = self.driver._allow_access(self._context, share, access)
        self.assertEqual(allow_access['driver_volume_type'],
                         share['share_proto'])
        self.assertEqual('1.1.1.1:3260',
                         allow_access['data']['target_portal'])
        (srv_name, srv_params) = RUNTIME_VARS['servers'][0]
        self.assertEqual(srv_params['iscsi'],
                         allow_access['data']['target_ip'])
        self.assertEqual(share['id'], allow_access['data']['id'])
        self.assertEqual('CHAP', allow_access['data']['auth_method'])
        self.assertEqual('test_chap_user',
                         allow_access['data']['auth_username'])
        self.assertEqual('test_chap_secret',
                         allow_access['data']['auth_password'])

        # Detach will not throw any error with missing access rules
        dup_access = fake_share.fake_access()
        self.driver._deny_access(self._context, share, dup_access)
        # Detach server from the share with deny access rules
        self.driver._deny_access(self._context, share, access)
        self.driver.delete_share(self._context, share)

    def create_vpsa_backend_share_snapshot(self, share):
        vpsasnap_params = {}
        vpsasnap_params['id'] = 'fakesnapid'
        vpsasnap_params['name'] = 'fakesnapname'
        vpsasnap_params['display-name'] = 'fakesnapname'
        vpsasnap_params['provider-location'] = 'fakesnaplocation'
        (vol_name, vol_params) = RUNTIME_VARS['volumes'][0]
        vol_params['snapshots'].append(vpsasnap_params)

    @mock.patch.object(requests.Session, 'request', FakeRequests)
    def test_manage_existing_snapshot(self):
        share = {'id': 'fake_id',
                 'share_id': 'fake_shareid',
                 'name': 'fake_name',
                 'display-name': 'fake_name',
                 'cg-name': 'fake_name',
                 'size': 1,
                 'capacity': 1,
                 'share_proto': 'NFS',
                 'pool': 'pool-0001',
                 'nfs-export-path': '10.2.1.56:/export/manage_id',
                 'provisioned-capacity': 1}

        self.driver.create_share(self._context, share)
        # Create a backend share that will be managed for manila
        self.create_vpsa_backend_share_snapshot(share)

        snapshot = {'id': 'manage_snapname',
                    'name': 'manage_snapname',
                    'display_name': 'manage_snapname',
                    'provider_location': 'fakesnaplocation',
                    'share': share}
        driver_options = {}

        self.driver.manage_existing_snapshot(snapshot, driver_options)

        # Check that the backend share has been renamed
        (vol_name, vol_params) = RUNTIME_VARS['volumes'][0]
        self.assertEqual(
            vol_params['snapshots'][0]['display-name'].split('-')[2],
            snapshot['display_name'])
        self.driver.delete_snapshot(self._context, snapshot)
        self.driver.delete_share(self._context, share)
