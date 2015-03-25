# Copyright (c) 2014 Huawei Technologies Co., Ltd.
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

"""Unit tests for the Huawei nas driver module."""


import os
import shutil
import tempfile
import time
import xml.dom.minidom

import mock
from oslo_serialization import jsonutils

from manila import context
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.huawei import huawei_helper
from manila.share.drivers.huawei import huawei_nas
from manila import test


def fake_sleep(time):
    pass


def data_session(url):
    if url == "/xx/sessions":
        data = """{"error":{"code":0},
                       "data":{"username":"admin",
                               "iBaseToken":"2001031430",
                               "deviceid":"210235G7J20000000000"}}"""
    if url == "sessions":
        data = '{"error":{"code":0},"data":{"ID":11}}'
    return data


def filesystem(method, fs_status_flag):
    if method == "DELETE":
        data = """{"error":{"code":0}}"""

    if method == "GET":
        if fs_status_flag:
            data = """{"error":{"code":0},
                    "data":{"HEALTHSTATUS":"1",
                    "RUNNINGSTATUS":"27"}}"""
        else:
            data = """{"error":{"code":0},
                    "data":{"HEALTHSTATUS":"0",
                    "RUNNINGSTATUS":"27"}}"""
    return data


class FakeHuaweiNasDriver(huawei_nas.HuaweiNasDriver):
    """Fake Huawei Storage, Rewrite some methods of HuaweiNasDriver."""

    def __init__(self, *args, **kwargs):
        huawei_nas.HuaweiNasDriver.__init__(self, *args, **kwargs)
        self.helper = FakeHuaweiNasHelper(self.configuration)


class FakeHuaweiNasHelper(huawei_helper.RestHelper):

    def __init__(self, *args, **kwargs):
        huawei_helper.RestHelper.__init__(self, *args, **kwargs)
        self.test_normal = True
        self.deviceid = None
        self.delete_flag = False
        self.allow_flag = False
        self.deny_flag = False
        self.create_snapflag = False
        self.setupserver_flag = False
        self.fs_status_flag = True
        self.create_share_flag = False
        self.snapshot_flag = True

    def _change_file_mode(self, filepath):
        pass

    def call(self, url, data=None, method=None):

        url = url.replace('http://100.115.10.69:8082/deviceManager/rest', '')
        url = url.replace('/210235G7J20000000000/', '')
        data = None

        if self.test_normal:
            if url == "/xx/sessions" or url == "sessions":
                data = data_session(url)

            if url == "storagepool":
                data = """{"error":{"code":0},
                    "data":[{"USERFREECAPACITY":"2097152",
                    "ID":"1",
                    "NAME":"OpenStack_Pool",
                    "USERTOTALCAPACITY":"4194304"}]}"""

            if url == "filesystem":
                data = """{"error":{"code":0},"data":{
                            "ID":"4"}}"""

            if url == "NFSHARE" or url == "CIFSHARE":
                if self.create_share_flag:
                    data = '{"error":{"code":31755596}}'
                else:
                    data = """{"error":{"code":0},"data":{
                         "ID":"10"}}"""

            if url == "NFSHARE?range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"1",
                    "FSID":"4",
                    "NAME":"test",
                    "SHAREPATH":"/share_fake_uuid/"}]}"""

            if url == "CIFSHARE?range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"2",
                    "FSID":"4",
                    "NAME":"test",
                    "SHAREPATH":"/share_fake_uuid/"}]}"""

            if url == "NFSHARE?range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"1",
                    "FSID":"4",
                    "NAME":"test_fail",
                    "SHAREPATH":"/share_fake_uuid_fail/"}]}"""

            if url == "CIFSHARE?range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"2",
                    "FSID":"4",
                    "NAME":"test_fail",
                    "SHAREPATH":"/share_fake_uuid_fail/"}]}"""

            if url == "NFSHARE/1" or url == "CIFSHARE/2":
                data = """{"error":{"code":0}}"""
                self.delete_flag = True

            if url == "FSSNAPSHOT":
                data = """{"error":{"code":0},"data":{
                            "ID":"3"}}"""
                self.create_snapflag = True

            if url == "FSSNAPSHOT/4@share_snapshot_fake_snapshot_uuid":
                if self.snapshot_flag:
                    data = """{"error":{"code":0},"data":{"ID":"3"}}"""
                else:
                    data = '{"error":{"code":1073754118}}'
                self.delete_flag = True

            if url == "FSSNAPSHOT/3" or url == "filesystem/4":
                data = """{"error":{"code":0}}"""
                self.delete_flag = True

            if url == "NFS_SHARE_AUTH_CLIENT"\
                      or url == "CIFS_SHARE_AUTH_CLIENT":
                data = """{"error":{"code":0}}"""
                self.allow_flag = True

            if url == "FSSNAPSHOT?TYPE=48&PARENTID=4"\
                      "&&sortby=TIMESTAMP,d&range=[0-2000]":
                data = """{"error":{"code":0},
                "data":[{"ID":"3",
                "NAME":"share_snapshot_fake_snapshot_uuid"}]}"""
                self.delete_flag = True

            if url == "NFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::1&range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"0",
                    "NAME":"100.112.0.1_fail"}]}"""

            if url == "CIFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::2&range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"0",
                    "NAME":"user_name_fail"}]}"""

            if url == "NFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::1&range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"5",
                    "NAME":"100.112.0.1"}]}"""

            if url == "CIFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::2&range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"6",
                    "NAME":"user_name"}]}"""

            if url == "NFS_SHARE_AUTH_CLIENT/5"\
                      or url == "CIFS_SHARE_AUTH_CLIENT/6":
                data = """{"error":{"code":0}}"""
                self.deny_flag = True

            if url == "NFSHARE/count" or url == "CIFSHARE/count":
                data = """{"error":{"code":0},"data":{
                            "COUNT":"196"}}"""

            if url == "NFS_SHARE_AUTH_CLIENT/count?filter=PARENTID::1"\
                      or url == "CIFS_SHARE_AUTH_CLIENT/count?filter="\
                      "PARENTID::2":
                data = """{"error":{"code":0},"data":{
                            "COUNT":"196"}}"""

            if url == "CIFSSERVICE":
                data = """{"error":{"code":0},"data":{
                            "RUNNINGSTATUS":"2"}}"""

            if url == "NFSSERVICE":
                data = """{"error":{"code":0},
                "data":{"RUNNINGSTATUS":"2",
                "SUPPORTV3":"true",
                "SUPPORTV4":"true"}}"""
                self.setupserver_flag = True

            if url == "FILESYSTEM?range=[0-8191]":
                data = """{"error":{"code":0},
                "data":[{"ID":"4",
                "NAME":"share_fake_uuid"}]}"""

            if url == "filesystem/4":
                data = filesystem(method, self.fs_status_flag)
                self.delete_flag = True

        else:
            data = '{"error":{"code":31755596}}'

        res_json = jsonutils.loads(data)
        return res_json


class HuaweiShareDriverTestCase(test.TestCase):
    """Tests GenericShareDriver."""

    def setUp(self):
        super(HuaweiShareDriverTestCase, self).setUp()

        self._context = context.get_admin_context()
        self.tmp_dir = tempfile.mkdtemp()
        self.fake_conf_file = self.tmp_dir + '/manila_huawei_conf.xml'
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.create_fake_conf_file()
        self.addCleanup(os.remove, self.fake_conf_file)

        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self.configuration = mock.Mock(spec=conf.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.network_config_group = 'fake_network_config_group'
        self.configuration.share_backend_name = 'fake_share_backend_name'
        self.configuration.driver_handles_share_servers = False
        self.configuration.manila_huawei_conf_file = self.fake_conf_file
        self.mock_object(time, 'sleep', fake_sleep)
        driver = FakeHuaweiNasDriver(configuration=self.configuration)
        self.driver = driver
        self.driver.helper.test_normal = True

        self.share_nfs = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
        }

        self.share_cifs = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'CIFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
        }

        self.nfs_snapshot = {
            'id': 'fake_snapshot_uuid',
            'share_name': 'share_fake_uuid',
            'share_id': 'fake_uuid',
            'display_name': 'snapshot',
            'name': 'fake_snapshot_name',
            'share_size': 1,
            'size': 1,
            'share_proto': 'NFS',
        }

        self.cifs_snapshot = {
            'id': 'fake_snapshot_uuid',
            'share_name': 'share_fake_uuid',
            'share_id': 'fake_uuid',
            'display_name': 'snapshot',
            'name': 'fake_snapshot_name',
            'share_size': 1,
            'size': 1,
            'share_proto': 'CIFS',
        }

        self.security_service = {
            'id': 'fake_id',
            'domain': 'FAKE',
            'server': 'fake_server',
            'user': 'fake_user',
            'password': 'fake_password',
        }

        self.access_ip = {
            'access_type': 'ip',
            'access_to': '100.112.0.1',
        }

        self.access_user = {
            'access_type': 'user',
            'access_to': 'user_name',
        }

        self.share_server = None
        self.helper = mock.Mock()
        self.driver._helpers = {'FAKE': self.helper}
        self.driver._licenses = ['fake']

        self.network_info = {
            'server_id': 'fake_server_id',
            'cidr': '10.0.0.0/24',
            'security_services': ['fake_ldap', 'fake_kerberos', 'fake_ad', ],
            'segmentation_id': '1000',
            'network_allocations': [
                {'id': 'fake_na_id_1', 'ip_address': 'fake_ip_1', },
                {'id': 'fake_na_id_2', 'ip_address': 'fake_ip_2', },
            ],
        }

    def test_login_success(self):
        deviceid = self.driver.helper.login()
        self.assertEqual("210235G7J20000000000", deviceid)

    def test_create_share_nfs_success(self):
        self.driver.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_create_share_cifs_success(self):
        self.driver.helper.login()
        location = self.driver.create_share(self._context, self.share_cifs,
                                            self.share_server)
        self.assertEqual("\\\\100.115.10.68\\share_fake_uuid", location)

    def test_login_fail(self):
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare, self.driver.helper.login)

    def test_create_share_nfs_fs_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_create_share_nfs_status_fail(self):
        self.driver.helper.login()
        self.driver.helper.fs_status_flag = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_create_share_cifs_fs_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_cifs,
                          self.share_server)

    def test_create_share_cifs_fail(self):
        self.driver.helper.login()
        self.driver.helper.create_share_flag = True
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_cifs,
                          self.share_server)

    def test_create_share_nfs_fail(self):
        self.driver.helper.login()
        self.driver.helper.create_share_flag = True
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_delete_share_nfs_success(self):
        self.driver.helper.login()
        self.driver.helper.delete_flag = False
        self.driver.delete_share(self._context,
                                 self.share_nfs, self.share_server)
        self.assertTrue(self.driver.helper.delete_flag)

    def test_delete_share_cifs_success(self):
        self.driver.helper.login()
        self.driver.helper.delete_flag = False
        self.driver.delete_share(self._context, self.share_cifs,
                                 self.share_server)
        self.assertTrue(self.driver.helper.delete_flag)

    def test_get_share_stats_refresh_false(self):
        self.driver._stats = {'fake_key': 'fake_value'}

        result = self.driver.get_share_stats(False)

        self.assertEqual(self.driver._stats, result)

    def test_get_share_stats_refresh_true(self):
        self.driver.helper.login()
        data = self.driver.get_share_stats(True)

        expected = {}
        expected["share_backend_name"] = "fake_share_backend_name"
        expected["driver_handles_share_servers"] = False
        expected["vendor_name"] = 'Huawei'
        expected["driver_version"] = '1.0'
        expected["storage_protocol"] = 'NFS_CIFS'
        expected['total_capacity_gb'] = 2
        expected['free_capacity_gb'] = 1
        expected['reserved_percentage'] = 0
        expected['QoS_support'] = False
        self.assertDictMatch(expected, data)

    def test_get_capacity_success(self):
        self.driver.helper.login()
        capacity = {}
        capacity = self.driver.helper._get_capacity()
        self.assertEqual(2, capacity['total_capacity'])
        self.assertEqual(1, capacity['free_capacity'])

    def test_allow_access_ip_success(self):
        self.driver.helper.login()
        self.allow_flag = False
        self.driver.allow_access(self._context,
                                 self.share_nfs,
                                 self.access_ip,
                                 self.share_server)
        self.assertTrue(self.driver.helper.allow_flag)

    def test_allow_access_user_success(self):
        self.driver.helper.login()
        self.allow_flag = False
        self.driver.allow_access(self._context, self.share_cifs,
                                 self.access_user, self.share_server)
        self.assertTrue(self.driver.helper.allow_flag)

    def test_allow_access_ip_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.allow_access, self._context,
                          self.share_nfs, self.access_ip, self.share_server)

    def test_allow_access_user_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.allow_access, self._context,
                          self.share_cifs, self.access_user, self.share_server)

    def test_deny_access_ip_success(self):
        self.driver.helper.login()
        self.deny_flag = False
        self.driver.deny_access(self._context, self.share_nfs,
                                self.access_ip, self.share_server)
        self.assertTrue(self.driver.helper.deny_flag)

    def test_deny_access_user_success(self):
        self.driver.helper.login()
        self.deny_flag = False
        self.driver.deny_access(self._context, self.share_cifs,
                                self.access_user, self.share_server)
        self.assertTrue(self.driver.helper.deny_flag)

    def test_deny_access_ip_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.deny_access, self._context,
                          self.share_nfs, self.access_ip, self.share_server)

    def test_deny_access_user_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.deny_access, self._context,
                          self.share_cifs, self.access_user, self.share_server)

    def test_create_nfs_snapshot_success(self):
        self.driver.helper.login()
        self.driver.helper.create_snapflag = False
        self.driver.create_snapshot(self._context, self.nfs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.helper.create_snapflag)

    def test_create_cifs_snapshot_success(self):
        self.driver.helper.login()
        self.driver.helper.create_snapflag = False
        self.driver.create_snapshot(self._context, self.cifs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.helper.create_snapflag)

    def test_delete_snapshot_success(self):
        self.driver.helper.login()
        self.driver.helper.delete_flag = False
        self.driver.helper.snapshot_flag = True
        self.driver.delete_snapshot(self._context, self.nfs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.helper.delete_flag)

    def test_delete_snapshot_not_exist_success(self):
        self.driver.helper.login()
        self.driver.helper.delete_flag = False
        self.driver.helper.snapshot_flag = False
        self.driver.delete_snapshot(self._context, self.nfs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.helper.delete_flag)

    def test_create_nfs_snapshot_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_snapshot, self._context,
                          self.nfs_snapshot, self.share_server)

    def test_create_cifs_snapshot_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_snapshot, self._context,
                          self.cifs_snapshot, self.share_server)

    def test_delete_nfs_snapshot_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.delete_snapshot, self._context,
                          self.nfs_snapshot, self.share_server)

    def test_delete_cifs_snapshot_fail(self):
        self.driver.helper.login()
        self.driver.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.delete_snapshot, self._context,
                          self.cifs_snapshot, self.share_server)

    def create_fake_conf_file(self):
        doc = xml.dom.minidom.Document()
        config = doc.createElement('Config')
        doc.appendChild(config)

        storage = doc.createElement('Storage')
        config.appendChild(storage)
        controllerip0 = doc.createElement('LogicalPortIP')
        controllerip0_text = doc.createTextNode('100.115.10.68')
        controllerip0.appendChild(controllerip0_text)
        storage.appendChild(controllerip0)
        username = doc.createElement('UserName')
        username_text = doc.createTextNode('admin')
        username.appendChild(username_text)
        storage.appendChild(username)
        userpassword = doc.createElement('UserPassword')
        userpassword_text = doc.createTextNode('Admin@storage')
        userpassword.appendChild(userpassword_text)
        storage.appendChild(userpassword)
        url = doc.createElement('RestURL')
        url_text = doc.createTextNode('http://100.115.10.69:8082/'
                                      'deviceManager/rest/')
        url.appendChild(url_text)
        storage.appendChild(url)
        lun = doc.createElement('Filesystem')
        config.appendChild(lun)
        storagepool = doc.createElement('StoragePool')
        waitinterval = doc.createElement('WaitInterval')
        waitinterval_text = doc.createTextNode('1')
        waitinterval.appendChild(waitinterval_text)

        timeout = doc.createElement('Timeout')
        timeout_text = doc.createTextNode('1')
        timeout.appendChild(timeout_text)

        pool_text = doc.createTextNode('OpenStack_Pool')
        storagepool.appendChild(pool_text)
        lun.appendChild(storagepool)
        lun.appendChild(waitinterval)
        lun.appendChild(timeout)

        prefetch = doc.createElement('Prefetch')
        prefetch.setAttribute('Type', '0')
        prefetch.setAttribute('Value', '0')
        lun.appendChild(prefetch)

        fakefile = open(self.fake_conf_file, 'w')
        fakefile.write(doc.toprettyxml(indent=''))
        fakefile.close()
