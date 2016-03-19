# Copyright 2015 Alex Meade
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
Unit Tests for manila.share.rpcapi.
"""

import copy

from oslo_config import cfg
from oslo_serialization import jsonutils

from manila.common import constants
from manila import context
from manila.share import rpcapi as share_rpcapi
from manila import test
from manila.tests import db_utils

CONF = cfg.CONF


class ShareRpcAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareRpcAPITestCase, self).setUp()
        self.context = context.get_admin_context()
        share = db_utils.create_share(
            availability_zone=CONF.storage_availability_zone,
            status=constants.STATUS_AVAILABLE
        )
        access = db_utils.create_access(share_id=share['id'])
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        share_replica = db_utils.create_share_replica(
            id='fake_replica',
            share_id='fake_share_id',
            host='fake_host',
        )
        share_server = db_utils.create_share_server()
        cg = {'id': 'fake_cg_id', 'host': 'fake_host'}
        cgsnapshot = {'id': 'fake_cg_id'}
        host = {'host': 'fake_host', 'capabilities': 1}
        self.fake_share = jsonutils.to_primitive(share)
        # mock out the getattr on the share db model object since jsonutils
        # doesn't know about those extra attributes to pull in
        self.fake_share['instance'] = jsonutils.to_primitive(share.instance)
        self.fake_share_replica = jsonutils.to_primitive(share_replica)
        self.fake_access = jsonutils.to_primitive(access)
        self.fake_snapshot = jsonutils.to_primitive(snapshot)
        self.fake_share_server = jsonutils.to_primitive(share_server)
        self.fake_cg = jsonutils.to_primitive(cg)
        self.fake_cgsnapshot = jsonutils.to_primitive(cgsnapshot)
        self.fake_host = jsonutils.to_primitive(host)
        self.ctxt = context.RequestContext('fake_user', 'fake_project')
        self.rpcapi = share_rpcapi.ShareAPI()

    def test_serialized_share_has_id(self):
        self.assertTrue('id' in self.fake_share)

    def _test_share_api(self, method, rpc_method, **kwargs):
        expected_retval = 'foo' if method == 'call' else None

        target = {
            "version": kwargs.pop('version', self.rpcapi.BASE_RPC_API_VERSION)
        }
        expected_msg = copy.deepcopy(kwargs)
        if 'share' in expected_msg and method != 'get_migration_info':
            share = expected_msg['share']
            del expected_msg['share']
            expected_msg['share_id'] = share['id']
        if 'share_instance' in expected_msg:
            share_instance = expected_msg.pop('share_instance', None)
            expected_msg['share_instance_id'] = share_instance['id']
        if 'cg' in expected_msg:
            cg = expected_msg['cg']
            del expected_msg['cg']
            expected_msg['cg_id'] = cg['id']
        if 'cgsnapshot' in expected_msg:
            snap = expected_msg['cgsnapshot']
            del expected_msg['cgsnapshot']
            expected_msg['cgsnapshot_id'] = snap['id']
        if 'access' in expected_msg:
            access = expected_msg['access']
            del expected_msg['access']
            expected_msg['access_rules'] = [access['id']]
        if 'host' in expected_msg:
            del expected_msg['host']
        if 'snapshot' in expected_msg:
            snapshot = expected_msg['snapshot']
            del expected_msg['snapshot']
            expected_msg['snapshot_id'] = snapshot['id']
        if 'dest_host' in expected_msg:
            del expected_msg['dest_host']
            expected_msg['host'] = self.fake_host
        if 'share_replica' in expected_msg:
            share_replica = expected_msg.pop('share_replica', None)
            expected_msg['share_replica_id'] = share_replica['id']
            expected_msg['share_id'] = share_replica['share_id']
        if 'replicated_snapshot' in expected_msg:
            snapshot = expected_msg.pop('replicated_snapshot', None)
            expected_msg['snapshot_id'] = snapshot['id']
            expected_msg['share_id'] = snapshot['share_id']

        if 'host' in kwargs:
            host = kwargs['host']
        elif 'cg' in kwargs:
            host = kwargs['cg']['host']
        elif 'share_instance' in kwargs:
            host = kwargs['share_instance']['host']
        elif 'share_server' in kwargs:
            host = kwargs['share_server']['host']
        elif 'share_replica' in kwargs:
            host = kwargs['share_replica']['host']
        elif 'replicated_snapshot' in kwargs:
            host = kwargs['share']['instance']['host']
        else:
            host = kwargs['share']['host']
        target['server'] = host
        target['topic'] = '%s.%s' % (CONF.share_topic, host)

        self.fake_args = None
        self.fake_kwargs = None

        def _fake_prepare_method(*args, **kwds):
            for kwd in kwds:
                self.assertEqual(target[kwd], kwds[kwd])
            return self.rpcapi.client

        def _fake_rpc_method(*args, **kwargs):
            self.fake_args = args
            self.fake_kwargs = kwargs
            if expected_retval:
                return expected_retval

        self.mock_object(self.rpcapi.client, "prepare", _fake_prepare_method)
        self.mock_object(self.rpcapi.client, rpc_method, _fake_rpc_method)

        retval = getattr(self.rpcapi, method)(self.ctxt, **kwargs)

        self.assertEqual(expected_retval, retval)
        expected_args = [self.ctxt, method]
        for arg, expected_arg in zip(self.fake_args, expected_args):
            self.assertEqual(expected_arg, arg)

        for kwarg, value in self.fake_kwargs.items():
            self.assertEqual(expected_msg[kwarg], value)

    def test_create_share_instance(self):
        self._test_share_api('create_share_instance',
                             rpc_method='cast',
                             version='1.4',
                             share_instance=self.fake_share,
                             host='fake_host1',
                             snapshot_id='fake_snapshot_id',
                             filter_properties=None,
                             request_spec=None)

    def test_delete_share_instance(self):
        self._test_share_api('delete_share_instance',
                             rpc_method='cast',
                             version='1.4',
                             share_instance=self.fake_share,
                             force=False)

    def test_allow_access(self):
        self._test_share_api('allow_access',
                             rpc_method='cast',
                             version='1.7',
                             share_instance=self.fake_share,
                             access=self.fake_access)

    def test_deny_access(self):
        self._test_share_api('deny_access',
                             rpc_method='cast',
                             version='1.7',
                             share_instance=self.fake_share,
                             access=self.fake_access)

    def test_create_snapshot(self):
        self._test_share_api('create_snapshot',
                             rpc_method='cast',
                             share=self.fake_share,
                             snapshot=self.fake_snapshot)

    def test_delete_snapshot(self):
        self._test_share_api('delete_snapshot',
                             rpc_method='cast',
                             snapshot=self.fake_snapshot,
                             host='fake_host')

    def test_delete_share_server(self):
        self._test_share_api('delete_share_server',
                             rpc_method='cast',
                             share_server=self.fake_share_server)

    def test_extend_share(self):
        self._test_share_api('extend_share',
                             rpc_method='cast',
                             version='1.2',
                             share=self.fake_share,
                             new_size=123,
                             reservations={'fake': 'fake'})

    def test_shrink_share(self):
        self._test_share_api('shrink_share',
                             rpc_method='cast',
                             version='1.3',
                             share=self.fake_share,
                             new_size=123)

    def test_create_consistency_group(self):
        self._test_share_api('create_consistency_group',
                             version='1.5',
                             rpc_method='cast',
                             cg=self.fake_cg,
                             host='fake_host1')

    def test_delete_consistency_group(self):
        self._test_share_api('delete_consistency_group',
                             version='1.5',
                             rpc_method='cast',
                             cg=self.fake_cg)

    def test_create_cgsnapshot(self):
        self._test_share_api('create_cgsnapshot',
                             version='1.5',
                             rpc_method='cast',
                             cgsnapshot=self.fake_cgsnapshot,
                             host='fake_host1')

    def test_delete_cgsnapshot(self):
        self._test_share_api('delete_cgsnapshot',
                             version='1.5',
                             rpc_method='cast',
                             cgsnapshot=self.fake_cgsnapshot,
                             host='fake_host1')

    def test_migration_start(self):
        fake_dest_host = self.Desthost()
        self._test_share_api('migration_start',
                             rpc_method='cast',
                             version='1.6',
                             share=self.fake_share,
                             dest_host=fake_dest_host,
                             force_host_copy=True,
                             notify=True)

    def test_migration_get_info(self):
        self._test_share_api('migration_get_info',
                             rpc_method='call',
                             version='1.6',
                             share_instance=self.fake_share)

    def test_migration_get_driver_info(self):
        self._test_share_api('migration_get_driver_info',
                             rpc_method='call',
                             version='1.6',
                             share_instance=self.fake_share)

    def test_migration_complete(self):
        self._test_share_api('migration_complete',
                             rpc_method='cast',
                             version='1.10',
                             share=self.fake_share,
                             share_instance_id='fake_ins_id',
                             new_share_instance_id='new_fake_ins_id')

    def test_migration_cancel(self):
        self._test_share_api('migration_cancel',
                             rpc_method='call',
                             version='1.10',
                             share=self.fake_share)

    def test_migration_get_progress(self):
        self._test_share_api('migration_get_progress',
                             rpc_method='call',
                             version='1.10',
                             share=self.fake_share)

    def test_delete_share_replica(self):
        self._test_share_api('delete_share_replica',
                             rpc_method='cast',
                             version='1.8',
                             share_replica=self.fake_share_replica,
                             force=False)

    def test_promote_share_replica(self):
        self._test_share_api('promote_share_replica',
                             rpc_method='cast',
                             version='1.8',
                             share_replica=self.fake_share_replica)

    def test_update_share_replica(self):
        self._test_share_api('update_share_replica',
                             rpc_method='cast',
                             version='1.8',
                             share_replica=self.fake_share_replica)

    def test_manage_snapshot(self):
        self._test_share_api('manage_snapshot',
                             rpc_method='cast',
                             version='1.9',
                             snapshot=self.fake_snapshot,
                             host='fake_host',
                             driver_options={'volume_snapshot_id': 'fake'})

    def test_unmanage_snapshot(self):
        self._test_share_api('unmanage_snapshot',
                             rpc_method='cast',
                             version='1.9',
                             snapshot=self.fake_snapshot,
                             host='fake_host')

    def test_create_replicated_snapshot(self):
        self._test_share_api('create_replicated_snapshot',
                             rpc_method='cast',
                             version='1.11',
                             replicated_snapshot=self.fake_snapshot,
                             share=self.fake_share)

    def test_delete_replicated_snapshot(self):
        self._test_share_api('delete_replicated_snapshot',
                             rpc_method='cast',
                             version='1.11',
                             replicated_snapshot=self.fake_snapshot,
                             share_id=self.fake_snapshot['share_id'],
                             force=False,
                             host='fake_host')

    class Desthost(object):
        host = 'fake_host'
        capabilities = 1
