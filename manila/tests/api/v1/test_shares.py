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
from oslo_serialization import jsonutils
import six
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


@ddt.ddt
class ShareAPITest(test.TestCase):
    """Share API Test."""

    def setUp(self):
        super(self.__class__, self).setUp()
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

    def test_share_create_with_dhss_true_and_network_notexist(self):
        fake_share_type = {
            'id': 'fake_volume_type_id',
            'name': 'fake_volume_type_name',
            'extra_specs': {
                'driver_handles_share_servers': True,
            }
        }
        self.mock_object(
            share_types, 'get_default_share_type',
            mock.Mock(return_value=fake_share_type),
        )
        CONF.set_default("default_share_type", fake_share_type['name'])
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(webob.exc.HTTPBadRequest,
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
                                snapshot_id=shr['snapshot_id'],
                                instance=dict(
                                    availability_zone=shr['availability_zone'],
                                    share_network_id=shr['share_network_id'])))
        self.mock_object(share_api.API, 'create', create_mock)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.mock_object(share_api.API, 'get', mock.Mock(
            return_value=mock.Mock(
                instance={'share_network_id': parent_share_net})))
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
                                snapshot_id=shr['snapshot_id'],
                                instance=dict(
                                    availability_zone=shr['availability_zone'],
                                    share_network_id=shr['share_network_id'])))
        self.mock_object(share_api.API, 'create', create_mock)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.mock_object(share_api.API, 'get', mock.Mock(
            return_value=mock.Mock(
                instance={'share_network_id': parent_share_net})))
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
                'instance': {'host': 'fake_host',
                             'share_network_id': 'fake_share_network_id'},
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
            shares[1]['instance']['host'], result['shares'][0]['host'])
        self.assertEqual(
            shares[1]['instance']['share_network_id'],
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

    def test_validate_cephx_id_invalid_with_period(self):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_cephx_id,
                          "client.manila")

    def test_validate_cephx_id_invalid_with_non_ascii(self):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._validate_cephx_id,
                          u"bj\u00F6rn")

    @ddt.data("alice", "alice_bob", "alice bob")
    def test_validate_cephx_id_valid(self, test_id):
        self.controller._validate_cephx_id(test_id)


def _fake_access_get(self, ctxt, access_id):

    class Access(object):
        def __init__(self, **kwargs):
            self.STATE_NEW = 'fake_new'
            self.STATE_ACTIVE = 'fake_active'
            self.STATE_ERROR = 'fake_error'
            self.params = kwargs
            self.params['state'] = self.STATE_NEW
            self.share_id = kwargs.get('share_id')
            self.id = access_id

        def __getitem__(self, item):
            return self.params[item]

    access = Access(access_id=access_id, share_id='fake_share_id')
    return access


@ddt.ddt
class ShareActionsTest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = shares.ShareController()
        self.mock_object(share_api.API, 'get', stubs.stub_share_get)

    @ddt.data(
        {'access_type': 'ip', 'access_to': '127.0.0.1'},
        {'access_type': 'user', 'access_to': '1' * 4},
        {'access_type': 'user', 'access_to': '1' * 32},
        {'access_type': 'user', 'access_to': 'fake\\]{.-_\'`;}['},
        {'access_type': 'user', 'access_to': 'MYDOMAIN\\Administrator'},
        {'access_type': 'cert', 'access_to': 'x'},
        {'access_type': 'cert', 'access_to': 'tenant.example.com'},
        {'access_type': 'cert', 'access_to': 'x' * 64},
    )
    def test_allow_access(self, access):
        self.mock_object(share_api.API,
                         'allow_access',
                         mock.Mock(return_value={'fake': 'fake'}))

        id = 'fake_share_id'
        body = {'os-allow_access': access}
        expected = {'access': {'fake': 'fake'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._allow_access(req, id, body)
        self.assertEqual(expected, res)

    @ddt.data(
        {'access_type': 'error_type', 'access_to': '127.0.0.1'},
        {'access_type': 'ip', 'access_to': 'localhost'},
        {'access_type': 'ip', 'access_to': '127.0.0.*'},
        {'access_type': 'ip', 'access_to': '127.0.0.0/33'},
        {'access_type': 'ip', 'access_to': '127.0.0.256'},
        {'access_type': 'user', 'access_to': '1'},
        {'access_type': 'user', 'access_to': '1' * 3},
        {'access_type': 'user', 'access_to': '1' * 33},
        {'access_type': 'user', 'access_to': 'root^'},
        {'access_type': 'cert', 'access_to': ''},
        {'access_type': 'cert', 'access_to': ' '},
        {'access_type': 'cert', 'access_to': 'x' * 65},
        {'access_type': 'cephx', 'access_to': 'alice'}
    )
    def test_allow_access_error(self, access):
        id = 'fake_share_id'
        body = {'os-allow_access': access}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._allow_access, req, id, body)

    def test_deny_access(self):
        def _stub_deny_access(*args, **kwargs):
            pass

        self.mock_object(share_api.API, "deny_access", _stub_deny_access)
        self.mock_object(share_api.API, "access_get", _fake_access_get)

        id = 'fake_share_id'
        body = {"os-deny_access": {"access_id": 'fake_acces_id'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res = self.controller._deny_access(req, id, body)
        self.assertEqual(202, res.status_int)

    def test_deny_access_not_found(self):
        def _stub_deny_access(*args, **kwargs):
            pass

        self.mock_object(share_api.API, "deny_access", _stub_deny_access)
        self.mock_object(share_api.API, "access_get", _fake_access_get)

        id = 'super_fake_share_id'
        body = {"os-deny_access": {"access_id": 'fake_acces_id'}}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller._deny_access,
                          req,
                          id,
                          body)

    def test_access_list(self):
        def _fake_access_get_all(*args, **kwargs):
            return [{"state": "fakestatus",
                     "id": "fake_share_id",
                     "access_type": "fakeip",
                     "access_to": "127.0.0.1"}]

        self.mock_object(share_api.API, "access_get_all",
                         _fake_access_get_all)
        id = 'fake_share_id'
        body = {"os-access_list": None}
        req = fakes.HTTPRequest.blank('/v1/tenant1/shares/%s/action' % id)
        res_dict = self.controller._access_list(req, id, body)
        expected = _fake_access_get_all()
        self.assertEqual(expected, res_dict['access_list'])

    def test_extend(self):
        id = 'fake_share_id'
        share = stubs.stub_share_get(None, None, id)
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(share_api.API, "extend")

        size = '123'
        body = {"os-extend": {'new_size': size}}
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        actual_response = self.controller._extend(req, id, body)

        share_api.API.get.assert_called_once_with(mock.ANY, id)
        share_api.API.extend.assert_called_once_with(
            mock.ANY, share, int(size))
        self.assertEqual(202, actual_response.status_int)

    @ddt.data({"os-extend": ""},
              {"os-extend": {"new_size": "foo"}},
              {"os-extend": {"new_size": {'foo': 'bar'}}})
    def test_extend_invalid_body(self, body):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._extend, req, id, body)

    @ddt.data({'source': exception.InvalidInput,
               'target': webob.exc.HTTPBadRequest},
              {'source': exception.InvalidShare,
               'target': webob.exc.HTTPBadRequest},
              {'source': exception.ShareSizeExceedsAvailableQuota,
               'target': webob.exc.HTTPForbidden})
    @ddt.unpack
    def test_extend_exception(self, source, target):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)
        body = {"os-extend": {'new_size': '123'}}
        self.mock_object(share_api.API, "extend",
                         mock.Mock(side_effect=source('fake')))

        self.assertRaises(target, self.controller._extend, req, id, body)

    def test_shrink(self):
        id = 'fake_share_id'
        share = stubs.stub_share_get(None, None, id)
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(share_api.API, "shrink")

        size = '123'
        body = {"os-shrink": {'new_size': size}}
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        actual_response = self.controller._shrink(req, id, body)

        share_api.API.get.assert_called_once_with(mock.ANY, id)
        share_api.API.shrink.assert_called_once_with(
            mock.ANY, share, int(size))
        self.assertEqual(202, actual_response.status_int)

    @ddt.data({"os-shrink": ""},
              {"os-shrink": {"new_size": "foo"}},
              {"os-shrink": {"new_size": {'foo': 'bar'}}})
    def test_shrink_invalid_body(self, body):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._shrink, req, id, body)

    @ddt.data({'source': exception.InvalidInput,
               'target': webob.exc.HTTPBadRequest},
              {'source': exception.InvalidShare,
               'target': webob.exc.HTTPBadRequest})
    @ddt.unpack
    def test_shrink_exception(self, source, target):
        id = 'fake_share_id'
        req = fakes.HTTPRequest.blank('/v1/shares/%s/action' % id)
        body = {"os-shrink": {'new_size': '123'}}
        self.mock_object(share_api.API, "shrink",
                         mock.Mock(side_effect=source('fake')))

        self.assertRaises(target, self.controller._shrink, req, id, body)


@ddt.ddt
class ShareAdminActionsAPITest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        CONF.set_default("default_share_type", None)
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.share_api = share_api.API()
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_share_data(self, share=None):
        if share is None:
            share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                          size='1',
                                          override_defaults=True)
        req = webob.Request.blank('/v2/fake/shares/%s/action' % share['id'])
        return share, req

    def _reset_status(self, ctxt, model, req, db_access_method,
                      valid_code, valid_status=None, body=None):
        if body is None:
            body = {'os-reset_status': {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps(body))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(fakes.app())

        # validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])
        else:
            actual_model = db_access_method(ctxt, model['id'])
            self.assertEqual(valid_status, actual_model['status'])

    @ddt.data(
        {
            'role': 'admin',
            'valid_code': 202,
            'valid_status': constants.STATUS_ERROR,
        },
        {
            'role': 'member',
            'valid_code': 403,
            'valid_status': constants.STATUS_AVAILABLE,
        },
    )
    @ddt.unpack
    def test_share_reset_status_with_different_roles(self, role, valid_code,
                                                     valid_status):
        share, req = self._setup_share_data()
        ctxt = self._get_context(role)

        self._reset_status(ctxt, share, req, db.share_get, valid_code,
                           valid_status)

    @ddt.data(*fakes.fixture_invalid_reset_status_body)
    def test_share_invalid_reset_status_body(self, body):
        share, req = self._setup_share_data()
        ctxt = self.admin_context

        self._reset_status(ctxt, share, req, db.share_get, 400,
                           constants.STATUS_AVAILABLE, body)

    def test_share_reset_status_for_missing(self):
        fake_share = {'id': 'missing-share-id'}
        req = webob.Request.blank('/v1/fake/shares/%s/action' %
                                  fake_share['id'])

        self._reset_status(self.admin_context, fake_share, req,
                           db.share_snapshot_get, 404)

    def _force_delete(self, ctxt, model, req, db_access_method, valid_code,
                      check_model_in_db=False):
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps({'os-force_delete': {}}))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(fakes.app())

        # validate response
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 202 and check_model_in_db:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])

    @ddt.data(
        {'role': 'admin', 'resp_code': 202},
        {'role': 'member', 'resp_code': 403},
    )
    @ddt.unpack
    def test_share_force_delete_with_different_roles(self, role, resp_code):
        share, req = self._setup_share_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, share, req, db.share_get, resp_code,
                           check_model_in_db=True)

    def test_share_force_delete_missing(self):
        share, req = self._setup_share_data(share={'id': 'fake'})
        ctxt = self._get_context('admin')

        self._force_delete(ctxt, share, req, db.share_get, 404)
