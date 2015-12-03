# Copyright (c) 2015 Hitachi Data Systems.
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
"""Testing of SQLAlchemy model classes."""

import ddt

from manila.common import constants
from manila import test
from manila.tests import db_utils


@ddt.ddt
class ShareTestCase(test.TestCase):
    """Testing of SQLAlchemy Share model class."""

    def setUp(self):
        super(ShareTestCase, self).setUp()

    @ddt.data(constants.STATUS_MANAGE_ERROR, constants.STATUS_CREATING,
              constants.STATUS_EXTENDING, constants.STATUS_DELETING,
              constants.STATUS_EXTENDING_ERROR,
              constants.STATUS_ERROR_DELETING, constants.STATUS_MANAGING,
              constants.STATUS_MANAGE_ERROR)
    def test_share_instance_available(self, status):

        instance_list = [
            db_utils.create_share_instance(status=constants.STATUS_AVAILABLE,
                                           share_id='fake_id'),
            db_utils.create_share_instance(status=status,
                                           share_id='fake_id')
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(constants.STATUS_AVAILABLE, share1.instance['status'])
        self.assertEqual(constants.STATUS_AVAILABLE, share2.instance['status'])

    @ddt.data([constants.STATUS_MANAGE_ERROR, constants.STATUS_CREATING],
              [constants.STATUS_ERROR_DELETING, constants.STATUS_DELETING],
              [constants.STATUS_ERROR, constants.STATUS_MANAGING],
              [constants.STATUS_UNMANAGE_ERROR, constants.STATUS_UNMANAGING],
              [constants.STATUS_INACTIVE, constants.STATUS_EXTENDING],
              [constants.STATUS_SHRINKING_ERROR, constants.STATUS_SHRINKING])
    @ddt.unpack
    def test_share_instance_not_transitional(self, status, trans_status):

        instance_list = [
            db_utils.create_share_instance(status=status,
                                           share_id='fake_id'),
            db_utils.create_share_instance(status=trans_status,
                                           share_id='fake_id')
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(status, share1.instance['status'])
        self.assertEqual(status, share2.instance['status'])

    def test_share_instance_creating(self):

        share = db_utils.create_share(status=constants.STATUS_CREATING)

        self.assertEqual(constants.STATUS_CREATING, share.instance['status'])
