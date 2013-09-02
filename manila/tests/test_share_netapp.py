# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

"""Unit tests for the NetApp NAS driver module."""

from mox import IgnoreArg
import random
import suds

from manila import context
from manila import exception
from manila.share.configuration import Configuration
from manila.share.drivers import netapp
from manila import test


class FakeObject(object):
    pass


class FakeRequest(object):
    def __init__(self, name=None, args=None):
        self.Name = name
        self.Args = args


class FakeStartResp(object):
    def __init__(self):
        self.Tag = random.randint(1, 100)
        self.Records = random.randint(1, 10)


class FakeStatus(object):
    def __init__(self, status):
        self.Status = status


class FakeAggregates(object):
    def __init__(self, max_aggr_id):
        class AggrSizeAvail(object):
            def __init__(self, filer_id, avail):
                self.AggregateSize = FakeObject()
                self.FilerId = filer_id
                self.AggregateName = 'filer%d:aggr0' % filer_id
                setattr(self.AggregateSize, 'SizeAvailable', avail)

        class AggregateInfo(object):
            def __init__(self):
                self.AggregateInfo = [AggrSizeAvail(1, 10),
                                      AggrSizeAvail(2, 20),
                                      AggrSizeAvail(3, 1),
                                      AggrSizeAvail(max_aggr_id, 50),
                                      AggrSizeAvail(5, 15)]

        self.Aggregates = AggregateInfo()


class FakeSnapshots(object):
    def __init__(self, snapshot_name, is_busy='false'):
        class Result(object):
            def __init__(self):
                self.snapshots = [{}]
                self.snapshots[0]['snapshot-info'] = [
                    {'name': [snapshot_name], 'busy': [is_busy]},
                    {'name': ['fakesnapname1'], 'busy': [is_busy]},
                    {'name': ['fakesnapname2'], 'busy': ['true']},
                ]

        self.Results = Result()


class FakeNfsRules(object):
    def __init__(self):
        class Rules(object):
            def __init__(self):
                self.rules = [
                    {'exports-rule-info-2': [
                        {'security-rules': [
                            {'security-rule-info': [
                                {'root': [
                                    {'exports-hostname-info': [
                                        {'name': 'allowed_host'},
                                        {'name': 'disallowed_host'}]}
                                ]}
                            ]}
                        ]}
                    ]}
                ]

        self.Results = Rules()


class FakeHost(object):
    def __init__(self, id):
        self.HostId = id


class FakeHostInfo(object):
    def __init__(self):
        self.Hosts = FakeObject()
        setattr(self.Hosts, 'HostInfo', [FakeHost(1), FakeHost(2)])


class FakeFilter(object):
    def __init__(self, id=0):
        self.ObjectNameOrId = id


class FakeTimestamp(object):
    def __init__(self, monitor_name='file_system', last_stamp=1):
        self.MonitorName = monitor_name
        self.LastMonitoringTimestamp = last_stamp


class NetAppShareDriverTestCase(test.TestCase):
    """Tests Netapp-specific share driver.
    """

    def setUp(self):
        super(NetAppShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self._db = self.mox.CreateMockAnything()
        self._driver = netapp.NetAppShareDriver(
            self._db,
            configuration=Configuration(None))
        self._driver._client = self.mox.CreateMock(netapp.NetAppApiClient)
        cifs_helper = self.mox.CreateMock(netapp.NetAppCIFSHelper)
        nfs_helper = self.mox.CreateMock(netapp.NetAppNFSHelper)
        self._driver._helpers = {'CIFS': cifs_helper, 'NFS': nfs_helper}

    def test_setup_check(self):
        self._driver._client.do_setup()
        self.mox.ReplayAll()
        self._driver.do_setup(self._context)

    def test_load_balancer(self):
        drv = self._driver
        max_aggr_id = 123

        drv._client.get_available_aggregates().AndReturn(
                                                FakeAggregates(max_aggr_id))

        self.mox.ReplayAll()

        aggr = drv._find_best_aggregate()

        self.assertEquals(max_aggr_id, aggr.FilerId)

    def test_allocate_container(self):
        drv = self._driver
        client = drv._client
        share = {'id': 'fakeshareid', 'size': 1}
        max_aggr_id = 123

        client.get_available_aggregates().AndReturn(
                                                FakeAggregates(max_aggr_id))
        client.send_request_to(max_aggr_id, 'volume-create', IgnoreArg())

        self.mox.ReplayAll()

        drv.allocate_container(self._context, share)

        self.assertEqual(max_aggr_id, drv._share_table[share['id']])

    def test_allocate_container_from_snapshot(self):
        drv = self._driver
        client = drv._client
        share_id = 'fakeshareid'
        share = {'id': share_id, 'size': 1}
        snapshot = {'id': 'fakesnapshotid', 'size': 1,
                    'share_id': share_id}
        max_aggr_id = 123

        drv._share_table[share_id] = max_aggr_id

        client.send_request_to(max_aggr_id, 'volume-clone-create', IgnoreArg())

        self.mox.ReplayAll()

        drv.allocate_container_from_snapshot(self._context, share, snapshot)

        self.assertEqual(max_aggr_id, drv._share_table[share['id']])

    def test_deallocate_container_target_exists(self):
        drv = self._driver
        client = drv._client
        share_id = 'share-vol_id'
        share = {'id': share_id, 'size': 1}
        max_aggr_id = 123

        client.get_available_aggregates().AndReturn(
            FakeAggregates(max_aggr_id))
        client.send_request_to(max_aggr_id, 'volume-create', IgnoreArg())
        client.send_request_to(max_aggr_id, 'volume-offline', IgnoreArg())
        client.send_request_to(max_aggr_id, 'volume-destroy', IgnoreArg())

        self.mox.ReplayAll()

        drv.allocate_container(self._context, share)
        drv.deallocate_container(self._context, share)

        self.assertEquals(len(drv._share_table.keys()), 0)

    def test_share_create(self):
        drv = self._driver
        ctx = self._context
        share_proto = 'CIFS'
        share = {'id': '1234-abcd-5678',
                 'share_proto': share_proto,
                 'size': 1}

        drv._helpers[share_proto].create_share(IgnoreArg(), share)

        self.mox.ReplayAll()

        drv.create_share(ctx, share)

    def test_share_delete(self):
        drv = self._driver
        ctx = self._context
        share_proto = 'NFS'
        helper = drv._helpers[share_proto]
        ip = '172.10.0.1'
        export = '/export_path'
        share = {'id': 'abcd-1234',
                 'share_proto': share_proto,
                 'export_location': ':'.join([ip, export])}
        fake_access_rules = [1, 2, 3]

        helper.get_target(share).AndReturn(ip)
        helper.delete_share(share)

        self.mox.ReplayAll()

        drv.delete_share(ctx, share)

    def test_create_snapshot(self):
        drv = self._driver
        client = drv._client
        share_id = 'fakeshareid'
        share = {'id': share_id, 'size': 1}
        snapshot = {'id': 'fakesnapshotid', 'size': 1,
                    'share_id': share_id}
        max_aggr_id = 123

        drv._share_table[share_id] = max_aggr_id

        client.send_request_to(max_aggr_id, 'snapshot-create', IgnoreArg())

        self.mox.ReplayAll()

        drv.create_snapshot(self._context, snapshot)

    def test_delete_snapshot(self):
        drv = self._driver
        client = drv._client
        share_id = 'fakeshareid'
        share = {'id': share_id, 'size': 1}
        snapshot = {'id': 'fakesnapshotid', 'size': 1,
                    'share_id': share_id}
        max_aggr_id = 123

        drv._share_table[share_id] = max_aggr_id

        client.send_request_to(max_aggr_id, 'snapshot-list-info', IgnoreArg(),
                               do_response_check=False).\
            AndReturn(FakeSnapshots(netapp._get_valid_snapshot_name(
                snapshot['id'])))
        client.send_request_to(max_aggr_id, 'snapshot-delete', IgnoreArg())

        self.mox.ReplayAll()

        drv.delete_snapshot(self._context, snapshot)

    def test_delete_snapshot_if_busy(self):
        drv = self._driver
        client = drv._client
        share_id = 'fakeshareid'
        share = {'id': share_id, 'size': 1}
        snapshot = {'id': 'fakesnapshotid', 'size': 1,
                    'share_id': share_id}
        max_aggr_id = 123

        drv._share_table[share_id] = max_aggr_id

        client.send_request_to(max_aggr_id, 'snapshot-list-info', IgnoreArg(),
                               do_response_check=False).\
            AndReturn(FakeSnapshots(netapp._get_valid_snapshot_name(
                snapshot['id']), is_busy='true'))

        self.mox.ReplayAll()

        self.assertRaises(exception.ShareSnapshotIsBusy, drv.delete_snapshot,
                          self._context, snapshot)

    def test_allow_access(self):
        drv = self._driver
        share_proto = 'CIFS'
        ctx = self._context
        share = {'share_proto': share_proto}
        access = {}

        drv._helpers[share_proto].allow_access(ctx, share, access)

        self.mox.ReplayAll()

        drv.allow_access(ctx, share, access)

    def test_deny_access(self):
        drv = self._driver
        share_proto = 'CIFS'
        ctx = self._context
        share = {'share_proto': share_proto}
        access = {}

        drv._helpers[share_proto].deny_access(ctx, share, access)

        self.mox.ReplayAll()

        drv.deny_access(ctx, share, access)

    def test_no_aggregates_available(self):
        drv = self._driver
        ctx = self._context
        share = None

        drv._client.get_available_aggregates().AndReturn(None)

        self.mox.ReplayAll()

        self.assertRaises(exception.Error, drv.allocate_container, ctx, share)


class NetAppNfsHelperTestCase(test.TestCase):
    """
    Tests Netapp-specific NFS driver.
    """
    def setUp(self):
        super(NetAppNfsHelperTestCase, self).setUp()

        fake_client = self.mox.CreateMock(netapp.NetAppApiClient)
        fake_conf = self.mox.CreateMock(Configuration)
        self._driver = netapp.NetAppNFSHelper(fake_client, fake_conf)

    def test_create_share(self):
        drv = self._driver
        client = drv._client
        target = 123
        share = {'id': 'abc-1234-567'}

        client.send_request_to(target, 'nfs-exportfs-append-rules-2',
                               IgnoreArg())
        client.get_host_ip_by(target).AndReturn('host:export')

        self.mox.ReplayAll()

        export = drv.create_share(target, share)

        self.assertEquals(export.find('-'), -1)

    def test_delete_share(self):
        drv = self._driver
        client = drv._client
        share = {'export_location': 'host:export'}

        client.send_request_to(IgnoreArg(), 'nfs-exportfs-delete-rules',
                               IgnoreArg())

        self.mox.ReplayAll()

        drv.delete_share(share)

    def test_invalid_allow_access(self):
        drv = self._driver
        share = None
        access = {'access_type': 'passwd'}  # passwd type is not supported

        self.assertRaises(exception.Error, drv.allow_access, context, share,
                          access)

    def test_allow_access(self):
        drv = self._driver
        client = drv._client
        share = {'export_location': 'host:export'}
        access = {'access_to': ['127.0.0.1', '127.0.0.2'],
                  'access_type': 'ip'}

        client.send_request_to(IgnoreArg(), 'nfs-exportfs-list-rules-2',
                               IgnoreArg()).AndReturn(FakeNfsRules())
        client.send_request_to(IgnoreArg(), 'nfs-exportfs-append-rules-2',
                               IgnoreArg())

        self.mox.ReplayAll()

        drv.allow_access(context, share, access)

    def test_deny_access(self):
        drv = self._driver
        client = drv._client
        share = {'export_location': 'host:export'}
        access = {'access_to': ['127.0.0.1', '127.0.0.2']}

        client.send_request_to(IgnoreArg(), 'nfs-exportfs-list-rules-2',
                               IgnoreArg()).AndReturn(FakeNfsRules())
        client.send_request_to(IgnoreArg(), 'nfs-exportfs-append-rules-2',
                               IgnoreArg())

        self.mox.ReplayAll()

        drv.deny_access(context, share, access)

    def test_get_target(self):
        drv = self._driver
        ip = '172.18.0.1'
        export_path = '/home'
        share = {'export_location': ':'.join([ip, export_path])}

        self.assertEquals(drv.get_target(share), ip)


class NetAppCifsHelperTestCase(test.TestCase):
    """
    Tests Netapp-specific CIFS driver.
    """
    def setUp(self):
        super(NetAppCifsHelperTestCase, self).setUp()

        fake_client = self.mox.CreateMock(netapp.NetAppApiClient)
        fake_conf = self.mox.CreateMock(Configuration)
        self._driver = netapp.NetAppCIFSHelper(fake_client, fake_conf)

    def tearDown(self):
        super(NetAppCifsHelperTestCase, self).tearDown()

    def test_create_share(self):
        drv = self._driver
        client = drv._client
        target = 123
        share = {'id': 'abc-1234-567'}
        ip = '172.0.0.1'

        client.send_request_to(target, 'cifs-status').AndReturn(
                                                        FakeStatus('stopped'))
        client.send_request_to(target, 'cifs-start',
                               do_response_check=False)
        client.send_request_to(target, 'system-cli', IgnoreArg())
        client.send_request_to(target, 'cifs-share-add', IgnoreArg())
        client.send_request_to(target, 'cifs-share-ace-delete', IgnoreArg())
        client.get_host_ip_by(target).AndReturn(ip)

        self.mox.ReplayAll()

        export = drv.create_share(target, share)

        self.assertEquals(export.find('-'), -1)
        self.assertTrue(export.startswith('//' + ip))

    def test_delete_share(self):
        drv = self._driver
        client = drv._client
        ip = '172.10.0.1'
        export = 'home'
        share = {'export_location': '//%s/%s' % (ip, export)}

        client.send_request_to(IgnoreArg(), 'cifs-share-delete', IgnoreArg())

        self.mox.ReplayAll()

        drv.delete_share(share)

    def test_allow_access_by_ip(self):
        drv = self._driver
        access = {'access_type': 'ip', 'access_to': '123.123.123.123'}
        share = None

        self.assertRaises(exception.Error, drv.allow_access, context, share,
                          access)

    def test_allow_access_by_passwd_invalid_user(self):
        drv = self._driver
        client = drv._client
        access = {'access_type': 'passwd', 'access_to': 'user:pass'}
        ip = '172.0.0.1'
        export = 'export_path'
        share = {'export_location': '//%s/%s' % (ip, export)}
        status = FakeStatus('failed')

        client.send_request_to(ip, 'useradmin-user-list', IgnoreArg(),
                               do_response_check=False).AndReturn(status)

        self.mox.ReplayAll()

        self.assertRaises(exception.Error, drv.allow_access, context, share,
                          access)

    def test_allow_access_by_passwd_existing_user(self):
        drv = self._driver
        client = drv._client
        access = {'access_type': 'passwd', 'access_to': 'user:pass'}
        ip = '172.0.0.1'
        export = 'export_path'
        share = {'export_location': '//%s/%s' % (ip, export)}
        status = FakeStatus('passed')

        client.send_request_to(ip, 'useradmin-user-list', IgnoreArg(),
                               do_response_check=False).AndReturn(status)
        client.send_request_to(ip, 'cifs-share-ace-set', IgnoreArg())

        self.mox.ReplayAll()

        drv.allow_access(context, share, access)

    def test_deny_access(self):
        drv = self._driver
        client = drv._client
        access = {'access_type': 'passwd', 'access_to': 'user:pass'}
        ip = '172.0.0.1'
        export = 'export_path'
        share = {'export_location': '//%s/%s' % (ip, export)}

        client.send_request_to(ip, 'cifs-share-ace-delete', IgnoreArg())

        self.mox.ReplayAll()

        drv.deny_access(context, share, access)

    def test_get_target(self):
        drv = self._driver
        ip = '172.10.0.1'
        export = 'export_path'
        share = {'export_location': '//%s/%s' % (ip, export)}

        self.assertEquals(drv.get_target(share), ip)


class NetAppNASHelperTestCase(test.TestCase):
    def setUp(self):
        super(NetAppNASHelperTestCase, self).setUp()

        fake_client = self.mox.CreateMock(suds.client.Client)
        fake_conf = self.mox.CreateMock(Configuration)
        self._driver = netapp.NetAppNASHelperBase(fake_client, fake_conf)

    def tearDown(self):
        super(NetAppNASHelperTestCase, self).tearDown()

    def test_create_share(self):
        drv = self._driver
        target_id = None
        share = None
        self.assertRaises(NotImplementedError, drv.create_share, target_id,
                          share)

    def test_delete_share(self):
        drv = self._driver
        share = None
        self.assertRaises(NotImplementedError, drv.delete_share, share)

    def test_allow_access(self):
        drv = self._driver
        share = None
        ctx = None
        access = None
        self.assertRaises(NotImplementedError, drv.allow_access, ctx, share,
                          access)

    def test_deny_access(self):
        drv = self._driver
        share = None
        ctx = None
        access = None
        self.assertRaises(NotImplementedError, drv.deny_access, ctx, share,
                          access)

    def test_get_target(self):
        drv = self._driver
        share = None
        self.assertRaises(NotImplementedError, drv.get_target, share)


class NetAppApiClientTestCase(test.TestCase):
    """Tests for NetApp DFM API client.
    """

    def setUp(self):
        super(NetAppApiClientTestCase, self).setUp()
        self.fake_conf = self.mox.CreateMock(Configuration)
        self._context = context.get_admin_context()
        self._driver = netapp.NetAppApiClient(self.fake_conf)

        self._driver._client = self.mox.CreateMock(suds.client.Client)
        self._driver._client.factory = self.mox.CreateMock(suds.client.Factory)
        # service object is generated dynamically from XML
        self._driver._client.service = self.mox.CreateMockAnything(
                                                suds.client.ServiceSelector)

    def test_get_host_by_ip(self):
        drv = self._driver
        client = drv._client
        service = client.service
        host_id = 123

        # can't use 'filter' because it's predefined in Python
        fltr = client.factory.create('HostListInfoIterStart').AndReturn(
                    FakeFilter())

        resp = service.HostListInfoIterStart(HostListInfoIterStart=fltr)
        resp = resp.AndReturn(FakeStartResp())
        service_list = service.HostListInfoIterNext(Tag=resp.Tag,
                                                    Maximum=resp.Records)
        service_list.AndReturn(FakeHostInfo())
        service.HostListInfoIterEnd(Tag=resp.Tag)

        self.mox.ReplayAll()

        drv.get_host_ip_by(host_id)

    def test_get_available_aggregates(self):
        drv = self._driver
        client = drv._client
        service = client.service

        resp = service.AggregateListInfoIterStart().AndReturn(FakeStartResp())
        service.AggregateListInfoIterNext(Tag=resp.Tag, Maximum=resp.Records)
        service.AggregateListInfoIterEnd(resp.Tag)

        self.mox.ReplayAll()

        drv.get_available_aggregates()

    def test_send_successfull_request(self):
        drv = self._driver
        client = drv._client
        service = client.service
        factory = client.factory

        target = 1
        args = '<xml></xml>'
        responce_check = False
        request = factory.create('Request').AndReturn(FakeRequest())

        service.ApiProxy(Target=target, Request=request)

        self.mox.ReplayAll()

        drv.send_request_to(target, request, args, responce_check)

    def test_send_failing_request(self):
        drv = self._driver
        client = drv._client
        service = client.service
        factory = client.factory

        target = 1
        args = '<xml></xml>'
        responce_check = True
        request = factory.create('Request').AndReturn(FakeRequest())

        service.ApiProxy(Target=target, Request=request).AndRaise(
                                        exception.Error())

        self.mox.ReplayAll()

        self.assertRaises(exception.Error, drv.send_request_to,
                          target, request, args, responce_check)

    def test_successfull_setup(self):
        drv = self._driver
        for flag in drv.REQUIRED_FLAGS:
            setattr(netapp.FLAGS, flag, 'val')
        conf_obj = Configuration(netapp.FLAGS)
        drv.check_configuration(conf_obj)

    def test_failing_setup(self):
        drv = self._driver
        self.assertRaises(exception.Error, drv.check_configuration,
                          Configuration(netapp.FLAGS))
