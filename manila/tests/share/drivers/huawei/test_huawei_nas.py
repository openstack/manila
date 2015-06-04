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
from manila.share.drivers.huawei import huawei_nas
from manila.share.drivers.huawei.v3 import connection
from manila.share.drivers.huawei.v3 import helper
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


def filesystem(method, data, fs_status_flag):
    extend_share_flag = False
    if method == "PUT":
        if data == """{"CAPACITY": 8388608}""":
            data = """{"error":{"code":0},
                "data":{"ID":"4",
                "CAPACITY":"8388608"}}"""
            extend_share_flag = True
    elif method == "DELETE":
        data = """{"error":{"code":0}}"""
    elif method == "GET":
        if fs_status_flag:
            data = """{"error":{"code":0},
                "data":{"HEALTHSTATUS":"1",
                "RUNNINGSTATUS":"27"}}"""
        else:
            data = """{"error":{"code":0},
                    "data":{"HEALTHSTATUS":"0",
                    "RUNNINGSTATUS":"27"}}"""
    else:
        data = '{"error":{"code":31755596}}'
    return (data, extend_share_flag)


def allow_access(type, method, data):
    allow_ro_flag = False
    allow_rw_flag = False
    access_nfs = {
        "TYPE": "16409",
        "NAME": "1.2.3.4",
        "PARENTID": "1",
        "ACCESSVAL": "0",
        "SYNC": "0",
        "ALLSQUASH": "1",
        "ROOTSQUASH": "0",
    }
    access_nfs_ro_data = jsonutils.dumps(access_nfs)
    access_nfs["NAME"] = "100.112.0.1"
    access_nfs["ACCESSVAL"] = "1"
    access_nfs_rw_data = jsonutils.dumps(access_nfs)

    access_cifs = {
        "NAME": "user_name",
        "PARENTID": "2",
        "PERMISSION": "0",
        "DOMAINTYPE": "2",
    }
    access_cifs_ro_data = jsonutils.dumps(access_cifs)

    access_cifs["PERMISSION"] = "5"
    access_cifs_rw_data = jsonutils.dumps(access_cifs)

    if method != "POST":
        data = """{"error":{"code":31755596}}"""
        return data

    if ((data == access_nfs_ro_data and type == "NFS")
       or (data == access_cifs_ro_data and type == "CIFS")):
        allow_ro_flag = True
        data = """{"error":{"code":0}}"""
    elif ((data == access_nfs_rw_data and type == 'NFS')
          or (data == access_cifs_rw_data and type == 'CIFS')):
        allow_rw_flag = True
        data = """{"error":{"code":0}}"""
    else:
        data = """{"error":{"code":31755596}}"""
    return (data, allow_ro_flag, allow_rw_flag)


class FakeHuaweiNasHelper(helper.RestHelper):

    def __init__(self, *args, **kwargs):
        helper.RestHelper.__init__(self, *args, **kwargs)
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
        self.service_status_flag = True
        self.share_exist = True
        self.service_nfs_status_flag = True
        self.create_share_data_flag = False
        self.allow_ro_flag = False
        self.allow_rw_flag = False
        self.extend_share_flag = False

    def _change_file_mode(self, filepath):
        pass

    def call(self, url, data=None, method=None):
        url = url.replace('http://100.115.10.69:8082/deviceManager/rest', '')
        url = url.replace('/210235G7J20000000000/', '')

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
                elif self.create_share_data_flag:
                    data = '{"error":{"code":0}}'
                else:
                    data = """{"error":{"code":0},"data":{
                         "ID":"10"}}"""

            if url == "NFSHARE?range=[100-200]":
                if self.share_exist:
                    data = """{"error":{"code":0},
                        "data":[{"ID":"1",
                        "FSID":"4",
                        "NAME":"test",
                        "SHAREPATH":"/share_fake_uuid/"}]}"""
                else:
                    data = """{"error":{"code":0},
                        "data":[{"ID":"1",
                        "FSID":"4",
                        "NAME":"test",
                        "SHAREPATH":"/share_fake_uuid_fail/"}]}"""

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

            if url == "FSSNAPSHOT/3":
                data = """{"error":{"code":0}}"""
                self.delete_flag = True

            if url == "NFS_SHARE_AUTH_CLIENT":
                data, self.allow_ro_flag, self.allow_rw_flag = \
                    allow_access('NFS', method, data)
                self.allow_flag = True

            if url == "CIFS_SHARE_AUTH_CLIENT":
                data, self.allow_ro_flag, self.allow_rw_flag = \
                    allow_access('CIFS', method, data)
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
                if self.service_status_flag:
                    data = """{"error":{"code":0},"data":{
                                "RUNNINGSTATUS":"2"}}"""
                else:
                    data = """{"error":{"code":0},"data":{
                                "RUNNINGSTATUS":"1"}}"""

            if url == "NFSSERVICE":
                if self.service_nfs_status_flag:
                    data = """{"error":{"code":0},
                    "data":{"RUNNINGSTATUS":"2",
                    "SUPPORTV3":"true",
                    "SUPPORTV4":"true"}}"""
                else:
                    data = """{"error":{"code":0},
                    "data":{"RUNNINGSTATUS":"1",
                    "SUPPORTV3":"true",
                    "SUPPORTV4":"true"}}"""
                self.setupserver_flag = True

            if url == "FILESYSTEM?range=[0-8191]":
                data = """{"error":{"code":0},
                "data":[{"ID":"4",
                "NAME":"share_fake_uuid"}]}"""

            if url == "filesystem/4":
                data, self.extend_share_flag = filesystem(method, data,
                                                          self.fs_status_flag)
                self.delete_flag = True

        else:
            data = '{"error":{"code":31755596}}'

        res_json = jsonutils.loads(data)
        return res_json


class FakeHuaweiNasDriver(huawei_nas.HuaweiNasDriver):
    """Fake HuaweiNasDriver."""

    def __init__(self, *args, **kwargs):
        huawei_nas.HuaweiNasDriver.__init__(self, *args, **kwargs)
        self.plugin = FakeV3StorageConnection(self.configuration)


class FakeV3StorageConnection(connection.V3StorageConnection):
    """Fake V3StorageConnection."""

    def __init__(self, configuration):
        connection.V3StorageConnection.__init__(self, configuration)
        self.configuration = configuration
        self.helper = FakeHuaweiNasHelper(self.configuration)


class HuaweiShareDriverTestCase(test.TestCase):
    """Tests GenericShareDriver."""

    def setUp(self):
        super(HuaweiShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self.tmp_dir = tempfile.mkdtemp()
        self.fake_conf_file = self.tmp_dir + '/manila_huawei_conf.xml'
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.create_fake_conf_file(self.fake_conf_file)
        self.addCleanup(os.remove, self.fake_conf_file)

        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self.configuration = mock.Mock(spec=conf.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.network_config_group = 'fake_network_config_group'
        self.configuration.share_backend_name = 'fake_share_backend_name'
        self.configuration.huawei_share_backend = 'V3'

        self.configuration.manila_huawei_conf_file = self.fake_conf_file
        self.configuration.driver_handles_share_servers = False
        self._helper_fake = mock.Mock()
        self.mock_object(huawei_nas.importutils, 'import_object',
                         mock.Mock(return_value=self._helper_fake))

        self.mock_object(time, 'sleep', fake_sleep)
        self.driver = FakeHuaweiNasDriver(configuration=self.configuration)
        self.driver.plugin.helper.test_normal = True

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

        self.share_proto_fail = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'proto_fail',
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
            'access_level': 'rw',
        }

        self.access_user = {
            'access_type': 'user',
            'access_to': 'user_name',
            'access_level': 'rw',
        }

        self.share_server = None
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

    def test_conf_product_fail(self):
        self.recreate_fake_conf_file(product_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_conf_file)

    def test_conf_pool_node_fail(self):
        self.recreate_fake_conf_file(pool_node_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_conf_file)

    def test_conf_username_fail(self):
        self.recreate_fake_conf_file(username_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_conf_file)

    def test_conf_timeout_fail(self):
        self.recreate_fake_conf_file(timeout_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        timeout = self.driver.plugin._get_timeout()
        self.assertEqual(60, timeout)

    def test_conf_wait_interval_fail(self):
        self.recreate_fake_conf_file(wait_interval_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        wait_interval = self.driver.plugin._get_wait_interval()
        self.assertEqual(3, wait_interval)

    def test_get_backend_driver_fail(self):
        test_fake_conf_file = None
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            test_fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver.get_backend_driver)

    def test_get_backend_driver_fail_driver_none(self):
        self.recreate_fake_conf_file(product_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver.get_backend_driver)

    def test_create_share_nfs_alloctype_fail(self):
        self.recreate_fake_conf_file(alloctype_value='alloctype_fail')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_create_share_nfs_storagepool_fail(self):
        self.recreate_fake_conf_file(pool_node_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_create_share_nfs_no_data_fail(self):
        self.driver.plugin.helper.create_share_data_flag = True
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_read_xml_fail(self):
        test_fake_conf_file = None
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            test_fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.helper._read_xml)

    def test_connect_fail(self):
        self.driver.plugin.configuration = None
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.connect)

    def test_login_success(self):
        deviceid = self.driver.plugin.helper.login()
        self.assertEqual("210235G7J20000000000", deviceid)

    def test_check_for_setup_success(self):
        self.driver.plugin.helper.login()
        self.driver.check_for_setup_error()

    def test_check_for_setup_service_down(self):
        self.driver.plugin.helper.service_status_flag = False
        self.driver.plugin.helper.login()
        self.driver.check_for_setup_error()

    def test_check_for_setup_nfs_down(self):
        self.driver.plugin.helper.service_nfs_status_flag = False
        self.driver.plugin.helper.login()
        self.driver.check_for_setup_error()

    def test_check_for_setup_service_false(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.check_for_setup_error)

    def test_create_share_nfs_alloctype_thin_success(self):
        self.recreate_fake_conf_file(alloctype_value='Thin')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_extend_share_success(self):
        self.driver.plugin.helper.extend_share_flag = False
        self.driver.plugin.helper.login()
        self.driver.extend_share(self.share_nfs, 4,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.extend_share_flag)

    def test_extend_share_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.extend_share,
                          self.share_nfs,
                          4,
                          self.share_server)

    def test_extend_share_not_exist(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.share_exist = False
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.extend_share,
                          self.share_nfs,
                          4,
                          self.share_server)

    def test_create_share_nfs_success(self):
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_create_share_cifs_success(self):
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_cifs,
                                            self.share_server)
        self.assertEqual("\\\\100.115.10.68\\share_fake_uuid", location)

    def test_login_fail(self):
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.plugin.helper.login)

    def test_create_share_nfs_fs_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_create_share_nfs_status_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.fs_status_flag = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_create_share_cifs_fs_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_cifs,
                          self.share_server)

    def test_create_share_cifs_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.create_share_flag = True
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_cifs,
                          self.share_server)

    def test_create_share_nfs_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.create_share_flag = True
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_delete_share_nfs_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        self.driver.delete_share(self._context,
                                 self.share_nfs, self.share_server)
        self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_check_snapshot_id_exist_fail(self):
        snapshot_id = "4"
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.plugin.helper._check_snapshot_id_exist,
                          snapshot_id)

    def test_delete_share_nfs_fail_not_exist(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        self.driver.plugin.helper.share_exist = False
        self.driver.delete_share(self._context,
                                 self.share_nfs, self.share_server)
        self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_delete_share_cifs_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        self.driver.delete_share(self._context, self.share_cifs,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_get_network_allocations_number(self):
        number = self.driver.get_network_allocations_number()
        self.assertEqual(0, number)

    def test_create_share_from_snapshot(self):
        self.assertRaises(NotImplementedError,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs, self.nfs_snapshot,
                          self.share_server)

    def test_get_share_stats_refresh(self):
        self.driver.plugin.helper.login()
        self.driver._update_share_stats()

        expected = {}
        expected["share_backend_name"] = "fake_share_backend_name"
        expected["driver_handles_share_servers"] = False
        expected["vendor_name"] = 'Huawei'
        expected["driver_version"] = '1.0'
        expected["storage_protocol"] = 'NFS_CIFS'
        expected['reserved_percentage'] = 0
        expected['total_capacity_gb'] = 'infinite'
        expected['free_capacity_gb'] = 'infinite'
        expected['QoS_support'] = False
        expected["pools"] = []
        pool = {}
        pool.update(dict(
            pool_name='OpenStack_Pool',
            total_capacity_gb=2,
            free_capacity_gb=1,
            QoS_support=False,
            reserved_percentage=0,
        ))
        expected["pools"].append(pool)
        self.assertEqual(expected, self.driver._stats)

    def test_get_capacity_success(self):
        self.driver.plugin.helper.login()
        capacity = {}
        capacity = self.driver.plugin._get_capacity()
        self.assertEqual(2, capacity['TOTALCAPACITY'])
        self.assertEqual(1, capacity['CAPACITY'])

    def test_allow_access_proto_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidInput,
                          self.driver.allow_access,
                          self._context,
                          self.share_proto_fail,
                          self.access_ip,
                          self.share_server)

    def test_allow_access_ip_rw_success(self):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        self.driver.allow_access(self._context,
                                 self.share_nfs,
                                 self.access_ip,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)

    def test_allow_access_ip_ro_success(self):
        access_ro = {
            'access_type': 'ip',
            'access_to': '1.2.3.4',
            'access_level': 'ro',
        }

        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_ro_flag = False
        self.driver.allow_access(self._context,
                                 self.share_nfs,
                                 access_ro,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_ro_flag)

    def test_allow_access_user_rw_success(self):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        self.driver.allow_access(self._context, self.share_cifs,
                                 self.access_user, self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)

    def test_allow_access_user_ro_success(self):
        access_ro = {
            'access_type': 'user',
            'access_to': 'user_name',
            'access_level': 'ro',
        }

        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_ro_flag = False
        self.driver.allow_access(self._context, self.share_cifs,
                                 access_ro, self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_ro_flag)

    def test_allow_access_level_fail(self):
        access_fail = {
            'access_type': 'user',
            'access_to': 'user_name',
            'access_level': 'fail',
        }

        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.allow_access,
                          self._context, self.share_cifs,
                          access_fail, self.share_server)

    def test_get_share_client_type_fail(self):
        share_proto = 'fake_proto'
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.helper._get_share_client_type,
                          share_proto)

    def test_get_share_type_fail(self):
        share_proto = 'fake_proto'
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.helper._get_share_type,
                          share_proto)

    def test_get_location_path_fail(self):
        share_name = 'share-fake-uuid'
        share_proto = 'fake_proto'
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.plugin._get_location_path, share_name,
                          share_proto)

    def test_allow_access_ip_proto_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.allow_access, self._context,
                          self.share_nfs, self.access_user, self.share_server)

    def test_allow_access_user_proto_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.allow_access, self._context,
                          self.share_cifs, self.access_ip, self.share_server)

    def test_deny_access_ip_proto_fail(self):
        self.driver.plugin.helper.login()
        result = self.driver.deny_access(self._context, self.share_nfs,
                                         self.access_user, self.share_server)
        self.assertEqual(None, result)

    def test_deny_access_user_proto_fail(self):
        self.driver.plugin.helper.login()
        result = self.driver.deny_access(self._context, self.share_cifs,
                                         self.access_ip, self.share_server)
        self.assertEqual(None, result)

    def test_allow_access_ip_share_not_exist(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.share_exist = False
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.allow_access, self._context,
                          self.share_nfs, self.access_ip, self.share_server)

    def test_deny_access_ip_share_not_exist(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.share_exist = False
        self.driver.deny_access(self._context, self.share_nfs,
                                self.access_ip, self.share_server)

    def test_allow_access_ip_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.allow_access, self._context,
                          self.share_nfs, self.access_ip, self.share_server)

    def test_allow_access_user_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.allow_access, self._context,
                          self.share_cifs, self.access_user, self.share_server)

    def test_deny_access_ip_success(self):
        self.driver.plugin.helper.login()
        self.deny_flag = False
        self.driver.deny_access(self._context, self.share_nfs,
                                self.access_ip, self.share_server)
        self.assertTrue(self.driver.plugin.helper.deny_flag)

    def test_deny_access_user_success(self):
        self.driver.plugin.helper.login()
        self.deny_flag = False
        self.driver.deny_access(self._context, self.share_cifs,
                                self.access_user, self.share_server)
        self.assertTrue(self.driver.plugin.helper.deny_flag)

    def test_deny_access_ip_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.deny_access, self._context,
                          self.share_nfs, self.access_ip, self.share_server)

    def test_deny_access_user_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.deny_access, self._context,
                          self.share_cifs, self.access_user, self.share_server)

    def test_create_nfs_snapshot_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.create_snapflag = False
        self.driver.create_snapshot(self._context, self.nfs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.plugin.helper.create_snapflag)

    def test_create_nfs_snapshot_share_not_exist(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.share_exist = False
        self.assertRaises(exception.InvalidInput,
                          self.driver.create_snapshot, self._context,
                          self.nfs_snapshot, self.share_server)

    def test_create_cifs_snapshot_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.create_snapflag = False
        self.driver.create_snapshot(self._context, self.cifs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.plugin.helper.create_snapflag)

    def test_delete_snapshot_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        self.driver.plugin.helper.snapshot_flag = True
        self.driver.delete_snapshot(self._context, self.nfs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_delete_snapshot_not_exist_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        self.driver.plugin.helper.snapshot_flag = False
        self.driver.delete_snapshot(self._context, self.nfs_snapshot,
                                    self.share_server)
        self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_create_nfs_snapshot_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_snapshot, self._context,
                          self.nfs_snapshot, self.share_server)

    def test_create_cifs_snapshot_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_snapshot, self._context,
                          self.cifs_snapshot, self.share_server)

    def test_delete_nfs_snapshot_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.delete_snapshot, self._context,
                          self.nfs_snapshot, self.share_server)

    def test_delete_cifs_snapshot_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.delete_snapshot, self._context,
                          self.cifs_snapshot, self.share_server)

    def create_fake_conf_file(self, fake_conf_file,
                              product_flag=True, username_flag=True,
                              pool_node_flag=True, timeout_flag=True,
                              wait_interval_flag=True,
                              alloctype_value='Thick'):
        doc = xml.dom.minidom.Document()
        config = doc.createElement('Config')
        doc.appendChild(config)

        storage = doc.createElement('Storage')
        config.appendChild(storage)

        controllerip0 = doc.createElement('LogicalPortIP')
        controllerip0_text = doc.createTextNode('100.115.10.68')
        controllerip0.appendChild(controllerip0_text)
        storage.appendChild(controllerip0)

        if product_flag:
            product_text = doc.createTextNode('V3')
        else:
            product_text = doc.createTextNode('V3_fail')

        product = doc.createElement('Product')
        product.appendChild(product_text)
        storage.appendChild(product)

        if username_flag:
            username_text = doc.createTextNode('admin')
        else:
            username_text = doc.createTextNode('')

        username = doc.createElement('UserName')
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
        if pool_node_flag:
            pool_text = doc.createTextNode('OpenStack_Pool')
        else:
            pool_text = doc.createTextNode('')
        storagepool.appendChild(pool_text)

        timeout = doc.createElement('Timeout')

        if timeout_flag:
            timeout_text = doc.createTextNode('0')
        else:
            timeout_text = doc.createTextNode('')
        timeout.appendChild(timeout_text)

        waitinterval = doc.createElement('WaitInterval')
        if wait_interval_flag:
            waitinterval_text = doc.createTextNode('0')
        else:
            waitinterval_text = doc.createTextNode('')
        waitinterval.appendChild(waitinterval_text)

        alloctype = doc.createElement('AllocType')
        alloctype_text = doc.createTextNode(alloctype_value)
        alloctype.appendChild(alloctype_text)

        lun.appendChild(timeout)
        lun.appendChild(alloctype)
        lun.appendChild(waitinterval)
        lun.appendChild(storagepool)

        prefetch = doc.createElement('Prefetch')
        prefetch.setAttribute('Type', '0')
        prefetch.setAttribute('Value', '0')
        lun.appendChild(prefetch)

        fakefile = open(fake_conf_file, 'w')
        fakefile.write(doc.toprettyxml(indent=''))
        fakefile.close()

    def recreate_fake_conf_file(self, product_flag=True, username_flag=True,
                                pool_node_flag=True, timeout_flag=True,
                                wait_interval_flag=True,
                                alloctype_value='Thick'):
        self.tmp_dir = tempfile.mkdtemp()
        self.fake_conf_file = self.tmp_dir + '/manila_huawei_conf.xml'
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.create_fake_conf_file(self.fake_conf_file, product_flag,
                                   username_flag, pool_node_flag,
                                   timeout_flag, wait_interval_flag,
                                   alloctype_value)
        self.addCleanup(os.remove, self.fake_conf_file)
