# Copyright 2011 OpenStack Foundation
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

import ddt
import webob

from manila.api.contrib import types_manage
from manila.common import constants
from manila import exception
from manila.share import share_types
from manila import test
from manila.tests.api import fakes
from manila.tests import fake_notifier


def stub_share_type(id):
    specs = {"key1": "value1",
             "key2": "value2",
             "key3": "value3",
             "key4": "value4",
             "key5": "value5"}
    return dict(id=id, name='share_type_%s' % str(id), extra_specs=specs)


def return_share_types_get_share_type(context, id):
    if id == "777":
        raise exception.ShareTypeNotFound(share_type_id=id)
    return stub_share_type(int(id))


def return_share_types_destroy(context, name):
    if name == "777":
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    pass


def return_share_types_with_volumes_destroy(context, id):
    if id == "1":
        raise exception.ShareTypeInUse(share_type_id=id)
    pass


def return_share_types_create(context, name, specs):
    pass


def return_share_types_get_by_name(context, name):
    if name == "777":
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    return stub_share_type(int(name.split("_")[2]))


def make_create_body(name="test_share_1", extra_specs=None,
                     spec_driver_handles_share_servers=True):
    if not extra_specs:
        extra_specs = {}

    if spec_driver_handles_share_servers is not None:
        extra_specs[constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS] =\
            spec_driver_handles_share_servers

    body = {
        "share_type": {
            "name": name,
            "extra_specs": extra_specs
        }
    }

    return body


@ddt.ddt
class ShareTypesManageApiTest(test.TestCase):
    def setUp(self):
        super(ShareTypesManageApiTest, self).setUp()
        self.flags(host='fake')
        self.controller = types_manage.ShareTypesManageController()

        """to reset notifier drivers left over from other api/contrib tests"""
        fake_notifier.reset()
        self.addCleanup(fake_notifier.reset)
        self.mock_object(share_types, 'create',
                         return_share_types_create)
        self.mock_object(share_types, 'get_share_type_by_name',
                         return_share_types_get_by_name)
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)
        self.mock_object(share_types, 'destroy',
                         return_share_types_destroy)

    def test_share_types_delete(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        self.controller._delete(req, 1)
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)

    def test_share_types_delete_not_found(self):
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank('/v2/fake/types/777')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller._delete,
                          req, '777')
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)

    def test_share_types_with_volumes_destroy(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        self.controller._delete(req, 1)
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)

    @ddt.data(make_create_body("share_type_1"),
              make_create_body(spec_driver_handles_share_servers="false"),
              make_create_body(spec_driver_handles_share_servers="true"),
              make_create_body(spec_driver_handles_share_servers="1"),
              make_create_body(spec_driver_handles_share_servers="0"),
              make_create_body(spec_driver_handles_share_servers="True"),
              make_create_body(spec_driver_handles_share_servers="False"),
              make_create_body(spec_driver_handles_share_servers="FalsE"))
    def test_create(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        res_dict = self.controller._create(req, body)
        self.assertEqual(1, len(fake_notifier.NOTIFICATIONS))
        self.assertEqual(2, len(res_dict))
        self.assertEqual('share_type_1', res_dict['share_type']['name'])
        self.assertEqual('share_type_1', res_dict['volume_type']['name'])

    @ddt.data(None,
              make_create_body(""),
              make_create_body("n" * 256),
              {'foo': {'a': 'b'}},
              {'share_type': 'string'},
              make_create_body(spec_driver_handles_share_servers=None),
              make_create_body(spec_driver_handles_share_servers=""),
              make_create_body(spec_driver_handles_share_servers=[]),
              )
    def test_create_invalid_request(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._create, req, body)
        self.assertEqual(0, len(fake_notifier.NOTIFICATIONS))
