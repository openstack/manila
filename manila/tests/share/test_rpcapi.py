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
        share = db_utils.create_share(
            availability_zone=CONF.storage_availability_zone,
            status=constants.STATUS_AVAILABLE
        )
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        share_replica = db_utils.create_share_replica(
            id='fake_replica',
            share_id='fake_share_id',
            host='fake_host',
        )
        share_server = db_utils.create_share_server()
        share_group = {'id': 'fake_share_group_id', 'host': 'fake_host'}
        share_group_snapshot = {'id': 'fake_share_group_id'}
        host = 'fake_host'
        self.fake_share = jsonutils.to_primitive(share)
        # mock out the getattr on the share db model object since jsonutils
        # doesn't know about those extra attributes to pull in
        self.fake_share['instance'] = jsonutils.to_primitive(share.instance)
        self.fake_share_replica = jsonutils.to_primitive(share_replica)
        self.fake_snapshot = jsonutils.to_primitive(snapshot)
        self.fake_snapshot['share_instance'] = jsonutils.to_primitive(
            snapshot.instance)
        self.fake_share_server = jsonutils.to_primitive(share_server)
        self.fake_share_group = jsonutils.to_primitive(share_group)
        self.fake_share_group_snapshot = jsonutils.to_primitive(
            share_group_snapshot)
        self.fake_host = jsonutils.to_primitive(host)
        self.ctxt = context.RequestContext('fake_user', 'fake_project')
        self.rpcapi = share_rpcapi.ShareAPI()

    def test_serialized_share_has_id(self):
        self.assertIn('id', self.fake_share)

    def _test_share_api(self, method, rpc_method, **kwargs):
        expected_retval = 'foo' if method == 'call' else None

        target = {
            "version": kwargs.pop('version', self.rpcapi.BASE_RPC_API_VERSION)
        }
        expected_msg = copy.deepcopy(kwargs)
        if 'share' in expected_msg and method != 'get_connection_info':
            share = expected_msg['share']
            del expected_msg['share']
            expected_msg['share_id'] = share['id']
        if 'share_instance' in expected_msg:
            share_instance = expected_msg.pop('share_instance', None)
            expected_msg['share_instance_id'] = share_instance['id']
        if 'share_group' in expected_msg:
            share_group = expected_msg['share_group']
            del expected_msg['share_group']
            expected_msg['share_group_id'] = share_group['id']
        if 'share_group_snapshot' in expected_msg:
            snap = expected_msg['share_group_snapshot']
            del expected_msg['share_group_snapshot']
            expected_msg['share_group_snapshot_id'] = snap['id']
        if 'host' in expected_msg:
            del expected_msg['host']
        if 'snapshot' in expected_msg:
            snapshot = expected_msg['snapshot']
            del expected_msg['snapshot']
            expected_msg['snapshot_id'] = snapshot['id']
        if 'dest_host' in expected_msg:
            del expected_msg['dest_host']
            expected_msg['dest_host'] = self.fake_host
        if 'share_replica' in expected_msg:
            share_replica = expected_msg.pop('share_replica', None)
            expected_msg['share_replica_id'] = share_replica['id']
            expected_msg['share_id'] = share_replica['share_id']
        if 'replicated_snapshot' in expected_msg:
            snapshot = expected_msg.pop('replicated_snapshot', None)
            expected_msg['snapshot_id'] = snapshot['id']
            expected_msg['share_id'] = snapshot['share_id']
        if 'src_share_instance' in expected_msg:
            share_instance = expected_msg.pop('src_share_instance', None)
            expected_msg['src_instance_id'] = share_instance['id']
        if 'update_access' in expected_msg:
            share_instance = expected_msg.pop('share_instance', None)
            expected_msg['share_instance_id'] = share_instance['id']
        if 'snapshot_instance' in expected_msg:
            snapshot_instance = expected_msg.pop('snapshot_instance', None)
            expected_msg['snapshot_instance_id'] = snapshot_instance['id']

        if 'host' in kwargs:
            host = kwargs['host']
        elif 'share_group' in kwargs:
            host = kwargs['share_group']['host']
        elif 'share_instance' in kwargs:
            host = kwargs['share_instance']['host']
        elif 'share_server' in kwargs:
            host = kwargs['share_server']['host']
        elif 'share_replica' in kwargs:
            host = kwargs['share_replica']['host']
        elif 'replicated_snapshot' in kwargs:
            host = kwargs['share']['instance']['host']
        elif 'share' in kwargs:
            host = kwargs['share']['host']
        else:
            host = self.fake_host
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

    def test_update_access(self):
        self._test_share_api('update_access',
                             rpc_method='cast',
                             version='1.14',
                             share_instance=self.fake_share)

    def test_create_snapshot(self):
        self._test_share_api('create_snapshot',
                             rpc_method='cast',
                             share=self.fake_share,
                             snapshot=self.fake_snapshot)

    def test_delete_snapshot(self):
        self._test_share_api('delete_snapshot',
                             rpc_method='cast',
                             snapshot=self.fake_snapshot,
                             host='fake_host',
                             force=False)

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

    def test_create_share_group(self):
        self._test_share_api('create_share_group',
                             version='1.16',
                             rpc_method='cast',
                             share_group=self.fake_share_group,
                             host='fake_host1')

    def test_delete_share_group(self):
        self._test_share_api('delete_share_group',
                             version='1.16',
                             rpc_method='cast',
                             share_group=self.fake_share_group)

    def test_create_share_group_snapshot(self):
        self._test_share_api(
            'create_share_group_snapshot',
            version='1.16',
            rpc_method='cast',
            share_group_snapshot=self.fake_share_group_snapshot,
            host='fake_host1')

    def test_delete_share_group_snapshot(self):
        self._test_share_api(
            'delete_share_group_snapshot',
            version='1.16',
            rpc_method='cast',
            share_group_snapshot=self.fake_share_group_snapshot,
            host='fake_host1')

    def test_migration_start(self):
        self._test_share_api('migration_start',
                             rpc_method='cast',
                             version='1.15',
                             share=self.fake_share,
                             dest_host=self.fake_host,
                             force_host_assisted_migration=True,
                             preserve_metadata=True,
                             writable=True,
                             nondisruptive=False,
                             preserve_snapshots=True,
                             new_share_network_id='fake_net_id',
                             new_share_type_id='fake_type_id')

    def test_connection_get_info(self):
        self._test_share_api('connection_get_info',
                             rpc_method='call',
                             version='1.12',
                             share_instance=self.fake_share)

    def test_migration_complete(self):
        self._test_share_api('migration_complete',
                             rpc_method='cast',
                             version='1.12',
                             src_share_instance=self.fake_share['instance'],
                             dest_instance_id='new_fake_ins_id')

    def test_migration_cancel(self):
        self._test_share_api('migration_cancel',
                             rpc_method='cast',
                             version='1.12',
                             src_share_instance=self.fake_share['instance'],
                             dest_instance_id='ins2_id')

    def test_migration_get_progress(self):
        self._test_share_api('migration_get_progress',
                             rpc_method='call',
                             version='1.12',
                             src_share_instance=self.fake_share['instance'],
                             dest_instance_id='ins2_id')

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

    def test_revert_to_snapshot(self):
        self._test_share_api('revert_to_snapshot',
                             rpc_method='cast',
                             version='1.18',
                             share=self.fake_share,
                             snapshot=self.fake_snapshot,
                             host='fake_host',
                             reservations={'fake': 'fake'})

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

    def test_provide_share_server(self):
        self._test_share_api('provide_share_server',
                             rpc_method='call',
                             version='1.12',
                             share_instance=self.fake_share['instance'],
                             share_network_id='fake_network_id',
                             snapshot_id='fake_snapshot_id')

    def test_create_share_server(self):
        self._test_share_api('create_share_server',
                             rpc_method='cast',
                             version='1.12',
                             share_instance=self.fake_share['instance'],
                             share_server_id='fake_server_id')

    def test_snapshot_update_access(self):
        self._test_share_api('snapshot_update_access',
                             rpc_method='cast',
                             version='1.17',
                             snapshot_instance=self.fake_snapshot[
                                 'share_instance'])
