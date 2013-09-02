# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NetApp
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
Unit Tests for manila.volume.rpcapi.
"""


from manila import context
from manila import db
from manila import flags
from manila.openstack.common import jsonutils
from manila.openstack.common import rpc
from manila.share import rpcapi as share_rpcapi
from manila import test


FLAGS = flags.FLAGS


class ShareRpcAPITestCase(test.TestCase):

    def setUp(self):
        self.context = context.get_admin_context()
        shr = {}
        shr['host'] = 'fake_host'
        shr['availability_zone'] = FLAGS.storage_availability_zone
        shr['status'] = "available"
        share = db.share_create(self.context, shr)
        acs = {}
        acs['access_type'] = "ip"
        acs['access_to'] = "123.123.123.123"
        acs['share_id'] = share['id']
        access = db.share_access_create(self.context, acs)
        snap = {}
        snap['share_id'] = share['id']
        snapshot = db.share_snapshot_create(self.context, snap)
        self.fake_share = jsonutils.to_primitive(share)
        self.fake_access = jsonutils.to_primitive(access)
        self.fake_snapshot = jsonutils.to_primitive(snapshot)
        super(ShareRpcAPITestCase, self).setUp()

    def test_serialized_share_has_id(self):
        self.assertTrue('id' in self.fake_share)

    def _test_share_api(self, method, rpc_method, **kwargs):
        ctxt = context.RequestContext('fake_user', 'fake_project')

        if 'rpcapi_class' in kwargs:
            rpcapi_class = kwargs['rpcapi_class']
            del kwargs['rpcapi_class']
        else:
            rpcapi_class = share_rpcapi.ShareAPI
        rpcapi = rpcapi_class()
        expected_retval = 'foo' if method == 'call' else None

        expected_version = kwargs.pop('version', rpcapi.BASE_RPC_API_VERSION)
        expected_msg = rpcapi.make_msg(method, **kwargs)
        if 'share' in expected_msg['args']:
            share = expected_msg['args']['share']
            del expected_msg['args']['share']
            expected_msg['args']['share_id'] = share['id']
        if 'access' in expected_msg['args']:
            access = expected_msg['args']['access']
            del expected_msg['args']['access']
            expected_msg['args']['access_id'] = access['id']
            del expected_msg['args']['share_id']
        if 'host' in expected_msg['args']:
            del expected_msg['args']['host']
        if 'snapshot' in expected_msg['args']:
            snapshot = expected_msg['args']['snapshot']
            del expected_msg['args']['snapshot']
            expected_msg['args']['snapshot_id'] = snapshot['id']

        expected_msg['version'] = expected_version

        if 'host' in kwargs:
            host = kwargs['host']
        else:
            host = kwargs['share']['host']
        expected_topic = '%s.%s' % (FLAGS.share_topic, host)

        self.fake_args = None
        self.fake_kwargs = None

        def _fake_rpc_method(*args, **kwargs):
            self.fake_args = args
            self.fake_kwargs = kwargs
            if expected_retval:
                return expected_retval

        self.stubs.Set(rpc, rpc_method, _fake_rpc_method)

        retval = getattr(rpcapi, method)(ctxt, **kwargs)

        self.assertEqual(retval, expected_retval)
        expected_args = [ctxt, expected_topic, expected_msg]
        for arg, expected_arg in zip(self.fake_args, expected_args):
            self.assertEqual(arg, expected_arg)

    def test_create_share(self):
        self._test_share_api('create_share',
                             rpc_method='cast',
                             share=self.fake_share,
                             host='fake_host1',
                             snapshot_id='fake_snapshot_id',
                             filter_properties=None,
                             request_spec=None)

    def test_delete_share(self):
        self._test_share_api('delete_share',
                             rpc_method='cast',
                             share=self.fake_share)

    def test_allow_access(self):
        self._test_share_api('allow_access',
                             rpc_method='cast',
                             share=self.fake_share,
                             access=self.fake_access)

    def test_deny_access(self):
        self._test_share_api('deny_access',
                             rpc_method='cast',
                             share=self.fake_share,
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
