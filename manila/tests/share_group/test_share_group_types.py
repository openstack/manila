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


"""Test of Share Type methods for Manila."""
import copy
import datetime

import ddt
import mock

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share_group import share_group_types
from manila import test


def create_share_group_type_dict(group_specs=None):
    return {
        'fake_type': {
            'name': 'fake1',
            'group_specs': group_specs
        }
    }


@ddt.ddt
class ShareGroupTypesTestCase(test.TestCase):

    fake_type = {
        'test': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 43, 24),
            'deleted': '0',
            'deleted_at': None,
            'group_specs': {},
            'id': u'fooid-1',
            'name': u'test',
            'updated_at': None
        }
    }
    fake_group_specs = {u'gold': u'True'}
    fake_share_group_type_id = u'fooid-2'
    fake_type_w_extra = {
        'test_with_extra': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 45, 31),
            'deleted': '0',
            'deleted_at': None,
            'group_specs': fake_group_specs,
            'id': fake_share_group_type_id,
            'name': u'test_with_extra',
            'updated_at': None
        }
    }

    fake_type_w_valid_extra = {
        'test_with_extra': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 45, 31),
            'deleted': '0',
            'deleted_at': None,
            'group_specs': {
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'
            },
            'id': u'fooid-2',
            'name': u'test_with_extra',
            'updated_at': None
        }
    }

    fake_types = fake_type.copy()
    fake_types.update(fake_type_w_extra)
    fake_types.update(fake_type_w_valid_extra)

    fake_share_group = {
        'id': u'fooid-1',
        'share_group_type_id': fake_share_group_type_id,
    }

    def setUp(self):
        super(ShareGroupTypesTestCase, self).setUp()
        self.context = context.get_admin_context()

    @ddt.data({}, fake_type, fake_type_w_extra, fake_types)
    def test_get_all_types(self, share_group_type):
        self.mock_object(
            db, 'share_group_type_get_all',
            mock.Mock(return_value=copy.deepcopy(share_group_type)))

        returned_type = share_group_types.get_all(self.context)

        self.assertItemsEqual(share_group_type, returned_type)

    def test_get_all_types_search(self):
        share_group_type = self.fake_type_w_extra
        search_filter = {"group_specs": {"gold": "True"}, 'is_public': True}
        self.mock_object(
            db, 'share_group_type_get_all',
            mock.Mock(return_value=share_group_type))

        returned_type = share_group_types.get_all(
            self.context, search_opts=search_filter)

        db.share_group_type_get_all.assert_called_once_with(
            mock.ANY, 0, filters={'is_public': True})
        self.assertItemsEqual(share_group_type, returned_type)
        search_filter = {"group_specs": {"gold": "False"}}
        returned_type = share_group_types.get_all(
            self.context, search_opts=search_filter)
        self.assertEqual({}, returned_type)

    def test_add_access(self):
        project_id = '456'
        share_group_type = share_group_types.create(self.context, 'type2', [])
        share_group_type_id = share_group_type.get('id')

        share_group_types.add_share_group_type_access(
            self.context, share_group_type_id, project_id)
        stype_access = db.share_group_type_access_get_all(
            self.context, share_group_type_id)

        self.assertIn(project_id, [a.project_id for a in stype_access])

    def test_add_access_invalid(self):
        self.assertRaises(
            exception.InvalidShareGroupType,
            share_group_types.add_share_group_type_access,
            'fake', None, 'fake')

    def test_remove_access(self):
        project_id = '456'
        share_group_type = share_group_types.create(
            self.context, 'type3', [], projects=['456'])
        share_group_type_id = share_group_type.get('id')

        share_group_types.remove_share_group_type_access(
            self.context, share_group_type_id, project_id)
        stype_access = db.share_group_type_access_get_all(
            self.context, share_group_type_id)

        self.assertNotIn(project_id, stype_access)

    def test_remove_access_invalid(self):
        self.assertRaises(
            exception.InvalidShareGroupType,
            share_group_types.remove_share_group_type_access,
            'fake', None, 'fake')
