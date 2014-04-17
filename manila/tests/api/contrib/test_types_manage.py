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

import webob

from manila.api.contrib import types_manage
from manila import exception
from manila.openstack.common.notifier import api as notifier_api
from manila.openstack.common.notifier import test_notifier
from manila.share import volume_types
from manila import test
from manila.tests.api import fakes


def stub_volume_type(id):
    specs = {"key1": "value1",
             "key2": "value2",
             "key3": "value3",
             "key4": "value4",
             "key5": "value5"}
    return dict(id=id, name='vol_type_%s' % str(id), extra_specs=specs)


def return_volume_types_get_volume_type(context, id):
    if id == "777":
        raise exception.VolumeTypeNotFound(volume_type_id=id)
    return stub_volume_type(int(id))


def return_volume_types_destroy(context, name):
    if name == "777":
        raise exception.VolumeTypeNotFoundByName(volume_type_name=name)
    pass


def return_volume_types_with_volumes_destroy(context, id):
    if id == "1":
        raise exception.VolumeTypeInUse(volume_type_id=id)
    pass


def return_volume_types_create(context, name, specs):
    pass


def return_volume_types_get_by_name(context, name):
    if name == "777":
        raise exception.VolumeTypeNotFoundByName(volume_type_name=name)
    return stub_volume_type(int(name.split("_")[2]))


def make_create_body(name):
    return {
        "volume_type": {
            "name": name,
            "extra_specs": {
                "key": "value",
            }
        }
    }


class VolumeTypesManageApiTest(test.TestCase):
    def setUp(self):
        super(VolumeTypesManageApiTest, self).setUp()
        self.flags(host='fake',
                   notification_driver=[test_notifier.__name__])
        self.controller = types_manage.VolumeTypesManageController()
        """to reset notifier drivers left over from other api/contrib tests"""
        notifier_api._reset_drivers()
        test_notifier.NOTIFICATIONS = []
        self.stubs.Set(volume_types, 'create',
                       return_volume_types_create)
        self.stubs.Set(volume_types, 'get_volume_type_by_name',
                       return_volume_types_get_by_name)
        self.stubs.Set(volume_types, 'get_volume_type',
                       return_volume_types_get_volume_type)
        self.stubs.Set(volume_types, 'destroy',
                       return_volume_types_destroy)

    def test_volume_types_delete(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)
        self.controller._delete(req, 1)
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 1)

    def test_volume_types_delete_not_found(self):
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank('/v2/fake/types/777')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller._delete,
                          req, '777')
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 1)

    def test_volume_types_with_volumes_destroy(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)
        self.controller._delete(req, 1)
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 1)

    def test_create(self):
        body = make_create_body("volume_type_1")
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)
        res_dict = self.controller._create(req, body)
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 1)
        self.assertEqual(1, len(res_dict))
        self.assertEqual('vol_type_1', res_dict['volume_type']['name'])

    def test_create_with_too_small_name(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._create, req, make_create_body(""))
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)

    def test_create_with_too_big_name(self):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller._create,
                          req, make_create_body("n" * 256))
        self.assertEqual(len(test_notifier.NOTIFICATIONS), 0)

    def _create_volume_type_bad_body(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types')
        req.method = 'POST'
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._create, req, body)

    def test_create_no_body(self):
        self._create_volume_type_bad_body(body=None)

    def test_create_missing_volume(self):
        self._create_volume_type_bad_body(body={'foo': {'a': 'b'}})

    def test_create_malformed_entity(self):
        self._create_volume_type_bad_body(body={'volume_type': 'string'})
