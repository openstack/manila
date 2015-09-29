# Copyright 2012 NetApp
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

import copy
import datetime

import ddt
import mock
from oslo_config import cfg
import webob

from manila.api import common
from manila.api.openstack import api_version_request as api_version
from manila.api.v1 import shares
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import api as share_api
from manila.share import share_types
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes
from manila.tests import db_utils
from manila import utils

CONF = cfg.CONF


def app():
    # no auth, just let environ['manila.context'] pass through
    api = fakes.router.APIRouter()
    mapper = fakes.urlmap.URLMap()
    mapper['/v1'] = api
    return mapper


@ddt.ddt
class ShareApiTest(test.TestCase):
    """Share Api Test."""
    def setUp(self):
        super(ShareApiTest, self).setUp()
        self.controller = shares.ShareController()
        self.mock_object(db, 'availability_zone_get')
        self.mock_object(share_api.API, 'get_all',
                         stubs.stub_get_all_shares)
        self.mock_object(share_api.API, 'get',
                         stubs.stub_share_get)
        self.mock_object(share_api.API, 'update', stubs.stub_share_update)
        self.mock_object(share_api.API, 'delete', stubs.stub_share_delete)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.maxDiff = None
        self.share = {
            "size": 100,
            "display_name": "Share Test Name",
            "display_description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "is_public": False,
        }
        self.create_mock = mock.Mock(
            return_value=stubs.stub_share(
                '1',
                display_name=self.share['display_name'],
                display_description=self.share['display_description'],
                size=100,
                share_proto=self.share['share_proto'].upper(),
                availability_zone=self.share['availability_zone'])
        )
        self.vt = {
            'id': 'fake_volume_type_id',
            'name': 'fake_volume_type_name',
        }
        CONF.set_default("default_share_type", None)

    def _get_expected_share_detailed_response(self, values=None, admin=False):
        share = {
            'id': '1',
            'name': 'displayname',
            'availability_zone': 'fakeaz',
            'description': 'displaydesc',
            'export_location': 'fake_location',
            'export_locations': ['fake_location', 'fake_location2'],
            'project_id': 'fakeproject',
            'host': 'fakehost',
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
            'share_proto': 'FAKEPROTO',
            'metadata': {},
            'size': 1,
            'snapshot_id': '2',
            'share_network_id': None,
            'status': 'fakestatus',
            'share_type': '1',
            'volume_type': '1',
            'snapshot_support': True,
            'is_public': False,
            'links': [
                {
                    'href': 'http://localhost/v1/fake/shares/1',
                    'rel': 'self'
                },
                {
                    'href': 'http://localhost/fake/shares/1',
                    'rel': 'bookmark'
                }
            ],
        }
        if values:
            if 'display_name' in values:
                values['name'] = values.pop('display_name')
            if 'display_description' in values:
                values['description'] = values.pop('display_description')
            share.update(values)
        if share.get('share_proto'):
            share['share_proto'] = share['share_proto'].upper()
        if admin:
            share['share_server_id'] = 'fake_share_server_id'
        return {'share': share}

    @ddt.data("1.0", "2.0", "2.1")
    def test_share_create_original(self, microversion):
        self.mock_object(share_api.API, 'create', self.create_mock)
        body = {"share": copy.deepcopy(self.share)}
        req = fakes.HTTPRequest.blank('/shares', version=microversion)

        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(self.share)
        expected['share'].pop('snapshot_support')
        self.assertEqual(expected, res_dict)

    @ddt.data("2.2", "2.3")
    def test_share_create_with_snapshot_support_without_cg(self, microversion):
        self.mock_object(share_api.API, 'create', self.create_mock)
        body = {"share": copy.deepcopy(self.share)}
        req = fakes.HTTPRequest.blank('/shares', version=microversion)

        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(self.share)
        self.assertEqual(expected, res_dict)

    @ddt.data("2.4", "2.5")
    def test_share_create_with_consistency_group(self, microversion):
        self.mock_object(share_api.API, 'create', self.create_mock)
        body = {"share": copy.deepcopy(self.share)}
        req = fakes.HTTPRequest.blank('/shares', version=microversion)

        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(self.share)
        expected['share']['consistency_group_id'] = None
        expected['share']['source_cgsnapshot_member_id'] = None
        if (api_version.APIVersionRequest(microversion) >=
                api_version.APIVersionRequest('2.5')):
            expected['share']['task_state'] = None
        self.assertEqual(expected, res_dict)

    def test_share_create_with_valid_default_share_type(self):
        self.mock_object(share_types, 'get_share_type_by_name',
                         mock.Mock(return_value=self.vt))
        CONF.set_default("default_share_type", self.vt['name'])
        self.mock_object(share_api.API, 'create', self.create_mock)

        body = {"share": copy.deepcopy(self.share)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(self.share)
        expected['share'].pop('snapshot_support')
        share_types.get_share_type_by_name.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.vt['name'])
        self.assertEqual(expected, res_dict)

    def test_share_create_with_invalid_default_share_type(self):
        self.mock_object(
            share_types, 'get_default_share_type',
            mock.Mock(side_effect=exception.ShareTypeNotFoundByName(
                self.vt['name'])),
        )
        CONF.set_default("default_share_type", self.vt['name'])
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(exception.ShareTypeNotFoundByName,
                          self.controller.create, req, {'share': self.share})
        share_types.get_default_share_type.assert_called_once_with()

    def test_share_create_with_share_net(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "share_network_id": "fakenetid"
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                share_network_id=shr['share_network_id']))
        self.mock_object(share_api.API, 'create', create_mock)
        self.mock_object(share_api.API, 'get_share_network', mock.Mock(
            return_value={'id': 'fakenetid'}))

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(shr)
        expected['share'].pop('snapshot_support')
        self.assertEqual(expected, res_dict)
        self.assertEqual("fakenetid",
                         create_mock.call_args[1]['share_network_id'])

    def test_migrate_share(self):
        share = db_utils.create_share()
        req = fakes.HTTPRequest.blank('/shares/%s/action' % share['id'],
                                      use_admin_context=True)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.api_version_request = api_version.APIVersionRequest('2.5')
        req.api_version_request.experimental = True
        body = {'os-migrate_share': {'host': 'fake_host'}}
        self.mock_object(share_api.API, 'migrate_share')
        self.controller.migrate_share(req, share['id'], body)

    def test_migrate_share_no_share_id(self):
        req = fakes.HTTPRequest.blank('/shares/%s/action' % 'fake_id',
                                      use_admin_context=True)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.api_version_request = api_version.APIVersionRequest('2.5')
        req.api_version_request.experimental = True
        body = {'os-migrate_share': {'host': 'fake_host'}}
        self.mock_object(share_api.API, 'migrate_share')
        self.mock_object(share_api.API, 'get',
                         mock.Mock(side_effect=[exception.NotFound]))
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.migrate_share,
                          req, 'fake_id', body)

    def test_migrate_share_no_host(self):
        share = db_utils.create_share()
        req = fakes.HTTPRequest.blank('/shares/%s/action' % share['id'],
                                      use_admin_context=True)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.api_version_request = api_version.APIVersionRequest('2.5')
        req.api_version_request.experimental = True
        body = {'os-migrate_share': {}}
        self.mock_object(share_api.API, 'migrate_share')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.migrate_share,
                          req, share['id'], body)

    def test_migrate_share_no_host_invalid_force_host_copy(self):
        share = db_utils.create_share()
        req = fakes.HTTPRequest.blank('/shares/%s/action' % share['id'],
                                      use_admin_context=True)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.api_version_request = api_version.APIVersionRequest('2.5')
        req.api_version_request.experimental = True
        body = {'os-migrate_share': {'host': 'fake_host',
                                     'force_host_copy': 'fake'}}
        self.mock_object(share_api.API, 'migrate_share')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.migrate_share,
                          req, share['id'], body)

    def test_share_create_from_snapshot_without_share_net_no_parent(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": None,
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                snapshot_id=shr['snapshot_id'],
                                share_network_id=shr['share_network_id']))
        self.mock_object(share_api.API, 'create', create_mock)
        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)
        expected = self._get_expected_share_detailed_response(shr)
        expected['share'].pop('snapshot_support')
        self.assertEqual(expected, res_dict)

    def test_share_create_from_snapshot_without_share_net_parent_exists(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": None,
        }
        parent_share_net = 444
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                snapshot_id=shr['snapshot_id'],
                                share_network_id=shr['share_network_id']))
        self.mock_object(share_api.API, 'create', create_mock)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.mock_object(share_api.API, 'get', mock.Mock(
            return_value={'share_network_id': parent_share_net}))
        self.mock_object(share_api.API, 'get_share_network', mock.Mock(
            return_value={'id': parent_share_net}))

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)
        expected = self._get_expected_share_detailed_response(shr)
        expected['share'].pop('snapshot_support')
        self.assertEqual(expected, res_dict)
        self.assertEqual(parent_share_net,
                         create_mock.call_args[1]['share_network_id'])

    def test_share_create_from_snapshot_with_share_net_equals_parent(self):
        parent_share_net = 444
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": parent_share_net
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                snapshot_id=shr['snapshot_id'],
                                share_network_id=shr['share_network_id']))
        self.mock_object(share_api.API, 'create', create_mock)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.mock_object(share_api.API, 'get', mock.Mock(
            return_value={'share_network_id': parent_share_net}))
        self.mock_object(share_api.API, 'get_share_network', mock.Mock(
            return_value={'id': parent_share_net}))

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)
        expected = self._get_expected_share_detailed_response(shr)
        expected['share'].pop('snapshot_support')
        self.assertEqual(expected, res_dict)
        self.assertEqual(parent_share_net,
                         create_mock.call_args[1]['share_network_id'])

    def test_share_create_from_snapshot_invalid_share_net(self):
        self.mock_object(share_api.API, 'create')
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": 1234
        }
        body = {"share": shr}
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          req,
                          body)

    def test_share_creation_fails_with_bad_size(self):
        shr = {"size": '',
               "name": "Share Test Name",
               "description": "Share Test Desc",
               "share_proto": "fakeproto",
               "availability_zone": "zone1:host1"}
        body = {"share": shr}
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(exception.InvalidInput,
                          self.controller.create,
                          req,
                          body)

    def test_share_create_no_body(self):
        body = {}
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          req,
                          body)

    def test_share_create_invalid_availability_zone(self):
        self.mock_object(
            db,
            'availability_zone_get',
            mock.Mock(side_effect=exception.AvailabilityZoneNotFound(id='id'))
        )
        body = {"share": copy.deepcopy(self.share)}

        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.create,
                          req,
                          body)

    def test_share_show(self):
        req = fakes.HTTPRequest.blank('/shares/1')
        expected = self._get_expected_share_detailed_response()
        expected['share'].pop('snapshot_support')

        res_dict = self.controller.show(req, '1')

        self.assertEqual(expected, res_dict)

    def test_share_show_with_consistency_group(self):
        req = fakes.HTTPRequest.blank('/shares/1', version='2.4')
        expected = self._get_expected_share_detailed_response()
        expected['share']['consistency_group_id'] = None
        expected['share']['source_cgsnapshot_member_id'] = None

        res_dict = self.controller.show(req, '1')

        self.assertEqual(expected, res_dict)

    def test_share_show_with_share_type_name(self):
        req = fakes.HTTPRequest.blank('/shares/1', version='2.6')
        res_dict = self.controller.show(req, '1')
        expected = self._get_expected_share_detailed_response()
        expected['share']['consistency_group_id'] = None
        expected['share']['source_cgsnapshot_member_id'] = None
        expected['share']['share_type_name'] = None
        expected['share']['task_state'] = None
        self.assertEqual(expected, res_dict)

    def test_share_show_admin(self):
        req = fakes.HTTPRequest.blank('/shares/1', use_admin_context=True)
        expected = self._get_expected_share_detailed_response(admin=True)
        expected['share'].pop('snapshot_support')

        res_dict = self.controller.show(req, '1')

        self.assertEqual(expected, res_dict)

    def test_share_show_no_share(self):
        self.mock_object(share_api.API, 'get',
                         stubs.stub_share_get_notfound)
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '1')

    def test_share_delete(self):
        req = fakes.HTTPRequest.blank('/shares/1')
        resp = self.controller.delete(req, 1)
        self.assertEqual(202, resp.status_int)

    def test_share_delete_in_consistency_group_param_not_provided(self):
        fake_share = stubs.stub_share('fake_share',
                                      consistency_group_id='fake_cg_id')
        self.mock_object(share_api.API, 'get',
                         mock.Mock(return_value=fake_share))
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.delete, req, 1)

    def test_share_delete_in_consistency_group(self):
        fake_share = stubs.stub_share('fake_share',
                                      consistency_group_id='fake_cg_id')
        self.mock_object(share_api.API, 'get',
                         mock.Mock(return_value=fake_share))
        req = fakes.HTTPRequest.blank(
            '/shares/1?consistency_group_id=fake_cg_id')
        resp = self.controller.delete(req, 1)
        self.assertEqual(202, resp.status_int)

    def test_share_delete_in_consistency_group_wrong_id(self):
        fake_share = stubs.stub_share('fake_share',
                                      consistency_group_id='fake_cg_id')
        self.mock_object(share_api.API, 'get',
                         mock.Mock(return_value=fake_share))
        req = fakes.HTTPRequest.blank(
            '/shares/1?consistency_group_id=not_fake_cg_id')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.delete, req, 1)

    def test_share_update(self):
        shr = self.share
        body = {"share": shr}

        req = fakes.HTTPRequest.blank('/share/1')
        res_dict = self.controller.update(req, 1, body)
        self.assertEqual(shr["display_name"], res_dict['share']["name"])
        self.assertEqual(shr["display_description"],
                         res_dict['share']["description"])
        self.assertEqual(shr['is_public'],
                         res_dict['share']['is_public'])

    def test_share_update_with_consistency_group(self):
        shr = self.share
        body = {"share": shr}

        req = fakes.HTTPRequest.blank('/share/1', version="2.4")
        res_dict = self.controller.update(req, 1, body)
        self.assertIsNone(res_dict['share']["consistency_group_id"])
        self.assertIsNone(res_dict['share']["source_cgsnapshot_member_id"])

    def test_share_not_updates_size(self):
        req = fakes.HTTPRequest.blank('/share/1')
        res_dict = self.controller.update(req, 1, {"share": self.share})
        self.assertNotEqual(res_dict['share']["size"], self.share["size"])

    def test_share_delete_no_share(self):
        self.mock_object(share_api.API, 'get',
                         stubs.stub_share_get_notfound)
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          1)

    def _share_list_summary_with_search_opts(self, use_admin_context):
        search_opts = {
            'name': 'fake_name',
            'status': constants.STATUS_AVAILABLE,
            'share_server_id': 'fake_share_server_id',
            'share_type_id': 'fake_share_type_id',
            'snapshot_id': 'fake_snapshot_id',
            'host': 'fake_host',
            'share_network_id': 'fake_share_network_id',
            'metadata': '%7B%27k1%27%3A+%27v1%27%7D',  # serialized k1=v1
            'extra_specs': '%7B%27k2%27%3A+%27v2%27%7D',  # serialized k2=v2
            'sort_key': 'fake_sort_key',
            'sort_dir': 'fake_sort_dir',
            'limit': '1',
            'offset': '1',
            'is_public': 'False',
        }
        # fake_key should be filtered for non-admin
        url = '/shares?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(url, use_admin_context=use_admin_context)

        shares = [
            {'id': 'id1', 'display_name': 'n1'},
            {'id': 'id2', 'display_name': 'n2'},
            {'id': 'id3', 'display_name': 'n3'},
        ]
        self.mock_object(share_api.API, 'get_all',
                         mock.Mock(return_value=shares))

        result = self.controller.index(req)

        search_opts_expected = {
            'display_name': search_opts['name'],
            'status': search_opts['status'],
            'share_server_id': search_opts['share_server_id'],
            'share_type_id': search_opts['share_type_id'],
            'snapshot_id': search_opts['snapshot_id'],
            'host': search_opts['host'],
            'share_network_id': search_opts['share_network_id'],
            'metadata': {'k1': 'v1'},
            'extra_specs': {'k2': 'v2'},
            'is_public': 'False',
        }
        if use_admin_context:
            search_opts_expected.update({'fake_key': 'fake_value'})
        share_api.API.get_all.assert_called_once_with(
            req.environ['manila.context'],
            sort_key=search_opts['sort_key'],
            sort_dir=search_opts['sort_dir'],
            search_opts=search_opts_expected,
        )
        self.assertEqual(1, len(result['shares']))
        self.assertEqual(shares[1]['id'], result['shares'][0]['id'])
        self.assertEqual(
            shares[1]['display_name'], result['shares'][0]['name'])

    def test_share_list_summary_with_search_opts_by_non_admin(self):
        self._share_list_summary_with_search_opts(use_admin_context=False)

    def test_share_list_summary_with_search_opts_by_admin(self):
        self._share_list_summary_with_search_opts(use_admin_context=True)

    def test_share_list_summary(self):
        self.mock_object(share_api.API, 'get_all',
                         stubs.stub_share_get_all_by_project)
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.index(req)
        expected = {
            'shares': [
                {
                    'name': 'displayname',
                    'id': '1',
                    'links': [
                        {
                            'href': 'http://localhost/v1/fake/shares/1',
                            'rel': 'self'
                        },
                        {
                            'href': 'http://localhost/fake/shares/1',
                            'rel': 'bookmark'
                        }
                    ],
                }
            ]
        }
        self.assertEqual(expected, res_dict)

    def _share_list_detail_with_search_opts(self, use_admin_context):
        search_opts = {
            'name': 'fake_name',
            'status': constants.STATUS_AVAILABLE,
            'share_server_id': 'fake_share_server_id',
            'share_type_id': 'fake_share_type_id',
            'snapshot_id': 'fake_snapshot_id',
            'host': 'fake_host',
            'share_network_id': 'fake_share_network_id',
            'metadata': '%7B%27k1%27%3A+%27v1%27%7D',  # serialized k1=v1
            'extra_specs': '%7B%27k2%27%3A+%27v2%27%7D',  # serialized k2=v2
            'sort_key': 'fake_sort_key',
            'sort_dir': 'fake_sort_dir',
            'limit': '1',
            'offset': '1',
            'is_public': 'False',
        }
        # fake_key should be filtered for non-admin
        url = '/shares/detail?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(url, use_admin_context=use_admin_context)

        shares = [
            {'id': 'id1', 'display_name': 'n1'},
            {
                'id': 'id2',
                'display_name': 'n2',
                'status': constants.STATUS_AVAILABLE,
                'snapshot_id': 'fake_snapshot_id',
                'share_type_id': 'fake_share_type_id',
                'host': 'fake_host',
                'share_network_id': 'fake_share_network_id',
            },
            {'id': 'id3', 'display_name': 'n3'},
        ]
        self.mock_object(share_api.API, 'get_all',
                         mock.Mock(return_value=shares))

        result = self.controller.detail(req)

        search_opts_expected = {
            'display_name': search_opts['name'],
            'status': search_opts['status'],
            'share_server_id': search_opts['share_server_id'],
            'share_type_id': search_opts['share_type_id'],
            'snapshot_id': search_opts['snapshot_id'],
            'host': search_opts['host'],
            'share_network_id': search_opts['share_network_id'],
            'metadata': {'k1': 'v1'},
            'extra_specs': {'k2': 'v2'},
            'is_public': 'False',
        }
        if use_admin_context:
            search_opts_expected.update({'fake_key': 'fake_value'})
        share_api.API.get_all.assert_called_once_with(
            req.environ['manila.context'],
            sort_key=search_opts['sort_key'],
            sort_dir=search_opts['sort_dir'],
            search_opts=search_opts_expected,
        )
        self.assertEqual(1, len(result['shares']))
        self.assertEqual(shares[1]['id'], result['shares'][0]['id'])
        self.assertEqual(
            shares[1]['display_name'], result['shares'][0]['name'])
        self.assertEqual(
            shares[1]['snapshot_id'], result['shares'][0]['snapshot_id'])
        self.assertEqual(
            shares[1]['status'], result['shares'][0]['status'])
        self.assertEqual(
            shares[1]['share_type_id'], result['shares'][0]['share_type'])
        self.assertEqual(
            shares[1]['snapshot_id'], result['shares'][0]['snapshot_id'])
        self.assertEqual(
            shares[1]['host'], result['shares'][0]['host'])
        self.assertEqual(
            shares[1]['share_network_id'],
            result['shares'][0]['share_network_id'])

    def test_share_list_detail_with_search_opts_by_non_admin(self):
        self._share_list_detail_with_search_opts(use_admin_context=False)

    def test_share_list_detail_with_search_opts_by_admin(self):
        self._share_list_detail_with_search_opts(use_admin_context=True)

    def _list_detail_common_expected(self):
        return {
            'shares': [
                {
                    'status': 'fakestatus',
                    'description': 'displaydesc',
                    'export_location': 'fake_location',
                    'export_locations': ['fake_location', 'fake_location2'],
                    'availability_zone': 'fakeaz',
                    'name': 'displayname',
                    'share_proto': 'FAKEPROTO',
                    'metadata': {},
                    'project_id': 'fakeproject',
                    'host': 'fakehost',
                    'id': '1',
                    'snapshot_id': '2',
                    'snapshot_support': True,
                    'share_network_id': None,
                    'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
                    'size': 1,
                    'share_type': '1',
                    'volume_type': '1',
                    'is_public': False,
                    'links': [
                        {
                            'href': 'http://localhost/v1/fake/shares/1',
                            'rel': 'self'
                        },
                        {
                            'href': 'http://localhost/fake/shares/1',
                            'rel': 'bookmark'
                        }
                    ],
                }
            ]
        }

    def _list_detail_test_common(self, req, expected):
        self.mock_object(share_api.API, 'get_all',
                         stubs.stub_share_get_all_by_project)
        res_dict = self.controller.detail(req)
        self.assertEqual(expected, res_dict)
        self.assertEqual(res_dict['shares'][0]['volume_type'],
                         res_dict['shares'][0]['share_type'])

    def test_share_list_detail(self):
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/shares/detail', environ=env)
        expected = self._list_detail_common_expected()
        expected['shares'][0].pop('snapshot_support')
        self._list_detail_test_common(req, expected)

    def test_share_list_detail_with_consistency_group(self):
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/shares/detail', environ=env,
                                      version="2.4")
        expected = self._list_detail_common_expected()
        expected['shares'][0]['consistency_group_id'] = None
        expected['shares'][0]['source_cgsnapshot_member_id'] = None
        self._list_detail_test_common(req, expected)

    def test_share_list_detail_with_task_state(self):
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/shares/detail', environ=env,
                                      version="2.5")
        expected = self._list_detail_common_expected()
        expected['shares'][0]['consistency_group_id'] = None
        expected['shares'][0]['source_cgsnapshot_member_id'] = None
        expected['shares'][0]['task_state'] = None
        self._list_detail_test_common(req, expected)

    def test_remove_invalid_options(self):
        ctx = context.RequestContext('fakeuser', 'fakeproject', is_admin=False)
        search_opts = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd'}
        expected_opts = {'a': 'a', 'c': 'c'}
        allowed_opts = ['a', 'c']
        common.remove_invalid_options(ctx, search_opts, allowed_opts)
        self.assertEqual(expected_opts, search_opts)

    def test_remove_invalid_options_admin(self):
        ctx = context.RequestContext('fakeuser', 'fakeproject', is_admin=True)
        search_opts = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd'}
        expected_opts = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd'}
        allowed_opts = ['a', 'c']
        common.remove_invalid_options(ctx, search_opts, allowed_opts)
        self.assertEqual(expected_opts, search_opts)
