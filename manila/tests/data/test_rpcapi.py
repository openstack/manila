# Copyright 2015, Hitachi Data Systems.
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
Unit Tests for manila.data.rpcapi
"""

import copy

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils

from manila.common import constants
from manila import context
from manila.data import rpcapi as data_rpcapi
from manila import test
from manila.tests import db_utils

CONF = cfg.CONF


class DataRpcAPITestCase(test.TestCase):

    def setUp(self):
        super(DataRpcAPITestCase, self).setUp()
        share = db_utils.create_share(
            availability_zone=CONF.storage_availability_zone,
            status=constants.STATUS_AVAILABLE
        )
        self.fake_share = jsonutils.to_primitive(share)

    def tearDown(self):
        super(DataRpcAPITestCase, self).tearDown()

    def _test_data_api(self, method, rpc_method, fanout=False, **kwargs):
        ctxt = context.RequestContext('fake_user', 'fake_project')
        rpcapi = data_rpcapi.DataAPI()
        expected_retval = 'foo' if method == 'call' else None

        target = {
            "fanout": fanout,
            "version": kwargs.pop('version', '1.0'),
        }
        expected_msg = copy.deepcopy(kwargs)

        self.fake_args = None
        self.fake_kwargs = None

        def _fake_prepare_method(*args, **kwds):
            for kwd in kwds:
                self.assertEqual(target[kwd], kwds[kwd])
            return rpcapi.client

        def _fake_rpc_method(*args, **kwargs):
            self.fake_args = args
            self.fake_kwargs = kwargs
            if expected_retval:
                return expected_retval

        with mock.patch.object(rpcapi.client, "prepare") as mock_prepared:
            mock_prepared.side_effect = _fake_prepare_method

            with mock.patch.object(rpcapi.client, rpc_method) as mock_method:
                mock_method.side_effect = _fake_rpc_method
                retval = getattr(rpcapi, method)(ctxt, **kwargs)
                self.assertEqual(expected_retval, retval)
                expected_args = [ctxt, method, expected_msg]
                for arg, expected_arg in zip(self.fake_args, expected_args):
                    self.assertEqual(expected_arg, arg)

    def test_migration_start(self):
        self._test_data_api('migration_start',
                            rpc_method='cast',
                            version='1.0',
                            share_id=self.fake_share['id'],
                            ignore_list=[],
                            share_instance_id='fake_ins_id',
                            dest_share_instance_id='dest_fake_ins_id',
                            connection_info_src={},
                            connection_info_dest={})

    def test_data_copy_cancel(self):
        self._test_data_api('data_copy_cancel',
                            rpc_method='call',
                            version='1.0',
                            share_id=self.fake_share['id'])

    def test_data_copy_get_progress(self):
        self._test_data_api('data_copy_get_progress',
                            rpc_method='call',
                            version='1.0',
                            share_id=self.fake_share['id'])
