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

import ddt
import mock
from oslo_serialization import jsonutils

from manila import context
from manila import db
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.huawei import huawei_nas
from manila.share.drivers.huawei.v3 import connection
from manila.share.drivers.huawei.v3 import helper
from manila.share.drivers.huawei.v3 import smartx
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
    shrink_share_flag = False

    if method == "PUT":
        if data == """{"CAPACITY": 10485760}""":
            data = """{"error":{"code":0},
                "data":{"ID":"4",
                "CAPACITY":"8388608"}}"""
            extend_share_flag = True
        elif data == """{"CAPACITY": 2097152}""":
            data = """{"error":{"code":0},
                "data":{"ID":"4",
                "CAPACITY":"2097152"}}"""
            shrink_share_flag = True
        elif data == """{"NAME": "share_fake_manage_uuid"}""":
            data = """{"error":{"code":0},
                "data":{"ID":"4",
                "CAPACITY":"8388608"}}"""
        elif data == jsonutils.dumps({"ENABLEDEDUP": True,
                                      "ENABLECOMPRESSION": True}):
            data = """{"error":{"code":0},
                "data":{"ID":"4",
                "CAPACITY":"8388608"}}"""
        elif data == jsonutils.dumps({"ENABLEDEDUP": False,
                                      "ENABLECOMPRESSION": False}):
            data = """{"error":{"code":0},
                "data":{"ID":"4",
                "CAPACITY":"8388608"}}"""
    elif method == "DELETE":
        data = """{"error":{"code":0}}"""
    elif method == "GET":
        if fs_status_flag:
            data = """{"error":{"code":0},
                "data":{"HEALTHSTATUS":"1",
                "RUNNINGSTATUS":"27",
                "ALLOCTYPE":"1",
                "CAPACITY":"8388608",
                "PARENTNAME":"OpenStack_Pool",
                "ENABLECOMPRESSION":"false",
                "ENABLEDEDUP":"false",
                "CACHEPARTITIONID":"",
                "SMARTCACHEPARTITIONID":""}}"""
        else:
            data = """{"error":{"code":0},
                    "data":{"HEALTHSTATUS":"0",
                    "RUNNINGSTATUS":"27",
                    "ALLOCTYPE":"0",
                    "CAPACITY":"8388608",
                    "PARENTNAME":"OpenStack_Pool",
                    "ENABLECOMPRESSION":"false",
                    "ENABLEDEDUP":"false",
                    "CACHEPARTITIONID":"",
                    "SMARTCACHEPARTITIONID":""}}"""
    else:
        data = '{"error":{"code":31755596}}'
    return (data, extend_share_flag, shrink_share_flag)


def filesystem_thick(method, data, fs_status_flag):
    extend_share_flag = False
    shrink_share_flag = False

    if method == "PUT":
        if data == """{"CAPACITY": 10485760}""":
            data = """{"error":{"code":0},
                "data":{"ID":"5",
                "CAPACITY":"8388608"}}"""
            extend_share_flag = True
        elif data == """{"CAPACITY": 2097152}""":
            data = """{"error":{"code":0},
                "data":{"ID":"5",
                "CAPACITY":"2097152"}}"""
            shrink_share_flag = True
        elif data == """{"NAME": "share_fake_uuid_thickfs"}""":
            data = """{"error":{"code":0},
                "data":{"ID":"5",
                "CAPACITY":"8388608"}}"""
        elif data == jsonutils.dumps({"ENABLEDEDUP": False,
                                      "ENABLECOMPRESSION": False}):
            data = """{"error":{"code":0},
                "data":{"ID":"5",
                "CAPACITY":"8388608"}}"""
    elif method == "DELETE":
        data = """{"error":{"code":0}}"""
    elif method == "GET":
        if fs_status_flag:
            data = """{"error":{"code":0},
                "data":{"HEALTHSTATUS":"1",
                "RUNNINGSTATUS":"27",
                "ALLOCTYPE":"0",
                "CAPACITY":"8388608",
                "PARENTNAME":"OpenStack_Pool_Thick",
                "ENABLECOMPRESSION":"false",
                "ENABLEDEDUP":"false",
                "CACHEPARTITIONID":"",
                "SMARTCACHEPARTITIONID":""}}"""
        else:
            data = """{"error":{"code":0},
                    "data":{"HEALTHSTATUS":"0",
                    "RUNNINGSTATUS":"27",
                    "ALLOCTYPE":"0",
                    "CAPACITY":"8388608",
                    "PARENTNAME":"OpenStack_Pool_Thick",
                    "ENABLECOMPRESSION":"false",
                    "ENABLEDEDUP":"false",
                    "CACHEPARTITIONID":"",
                    "SMARTCACHEPARTITIONID":""}}"""
    else:
        data = '{"error":{"code":31755596}}'
    return (data, extend_share_flag, shrink_share_flag)


def filesystem_inpartition(method, data, fs_status_flag):
    extend_share_flag = False
    shrink_share_flag = False

    if method == "PUT":
        if data == """{"CAPACITY": 10485760}""":
            data = """{"error":{"code":0},
                "data":{"ID":"6",
                "CAPACITY":"8388608"}}"""
            extend_share_flag = True
        elif data == """{"CAPACITY": 2097152}""":
            data = """{"error":{"code":0},
                "data":{"ID":"6",
                "CAPACITY":"2097152"}}"""
            shrink_share_flag = True
        elif data == """{"NAME": "share_fake_manage_uuid"}""":
            data = """{"error":{"code":0},
                "data":{"ID":"6",
                "CAPACITY":"8388608"}}"""
        elif data == """{"NAME": "share_fake_uuid_inpartition"}""":
            data = """{"error":{"code":0},
                "data":{"ID":"6",
                "CAPACITY":"8388608"}}"""
        elif data == jsonutils.dumps({"ENABLEDEDUP": True,
                                      "ENABLECOMPRESSION": True}):
            data = """{"error":{"code":0},
                "data":{"ID":"6",
                "CAPACITY":"8388608"}}"""
        elif data == jsonutils.dumps({"ENABLEDEDUP": False,
                                      "ENABLECOMPRESSION": False}):
            data = """{"error":{"code":0},
                "data":{"ID":"6",
                "CAPACITY":"8388608"}}"""
    elif method == "DELETE":
        data = """{"error":{"code":0}}"""
    elif method == "GET":
        if fs_status_flag:
            data = """{"error":{"code":0},
                "data":{"HEALTHSTATUS":"1",
                "RUNNINGSTATUS":"27",
                "ALLOCTYPE":"1",
                "CAPACITY":"8388608",
                "PARENTNAME":"OpenStack_Pool",
                "ENABLECOMPRESSION":"false",
                "ENABLEDEDUP":"false",
                "CACHEPARTITIONID":"1",
                "SMARTCACHEPARTITIONID":"1"}}"""
        else:
            data = """{"error":{"code":0},
                    "data":{"HEALTHSTATUS":"0",
                    "RUNNINGSTATUS":"27",
                    "ALLOCTYPE":"0",
                    "CAPACITY":"8388608",
                    "PARENTNAME":"OpenStack_Pool",
                    "ENABLECOMPRESSION":"false",
                    "ENABLEDEDUP":"false",
                    "CACHEPARTITIONID":"1",
                    "SMARTCACHEPARTITIONID":"1"}}"""
    else:
        data = '{"error":{"code":31755596}}'
    return (data, extend_share_flag, shrink_share_flag)


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
        self.shrink_share_flag = False
        self.add_fs_to_partition_flag = False
        self.add_fs_to_cache_flag = False
        self.test_multi_url_flag = 0
        self.cache_exist = True
        self.partition_exist = True

    def _change_file_mode(self, filepath):
        pass

    def do_call(self, url, data=None, method=None, calltimeout=4):
        url = url.replace('http://100.115.10.69:8082/deviceManager/rest', '')
        url = url.replace('/210235G7J20000000000/', '')

        if self.test_normal:
            if self.test_multi_url_flag == 1:
                data = '{"error":{"code":-403}}'
                res_json = jsonutils.loads(data)
                return res_json
            elif self.test_multi_url_flag == 2:
                if ('http://100.115.10.70:8082/deviceManager/rest/xx/'
                   'sessions' == url):
                    self.url = url
                    data = data_session("/xx/sessions")
                    res_json = jsonutils.loads(data)
                    return res_json
                elif (('/xx/sessions' == url) or (self.url is not None
                      and 'http://100.115.10.69:8082/deviceManager/rest'
                      in self.url)):
                    data = '{"error":{"code":-403}}'
                    res_json = jsonutils.loads(data)
                    return res_json

            if url == "/xx/sessions" or url == "/sessions":
                data = data_session(url)

            if url == "/storagepool":
                data = """{"error":{"code":0},
                    "data":[{"USERFREECAPACITY":"2097152",
                    "ID":"1",
                    "NAME":"OpenStack_Pool",
                    "USERTOTALCAPACITY":"4194304",
                    "USAGETYPE":"2",
                    "USERCONSUMEDCAPACITY":"2097152"},
                    {"USERFREECAPACITY":"2097152",
                    "ID":"2",
                    "NAME":"OpenStack_Pool_Thick",
                    "USERTOTALCAPACITY":"4194304",
                    "USAGETYPE":"2",
                    "USERCONSUMEDCAPACITY":"2097152"}]}"""

            if url == "/filesystem":
                data = """{"error":{"code":0},"data":{
                            "ID":"4"}}"""

            if url == "/NFSHARE" or url == "/CIFSHARE":
                if self.create_share_flag:
                    data = '{"error":{"code":31755596}}'
                elif self.create_share_data_flag:
                    data = '{"error":{"code":0}}'
                else:
                    data = """{"error":{"code":0},"data":{
                         "ID":"10"}}"""

            if url == "/NFSHARE?range=[100-200]":
                if self.share_exist:
                    data = """{"error":{"code":0},
                        "data":[{"ID":"1",
                        "FSID":"4",
                        "NAME":"test",
                        "SHAREPATH":"/share_fake_uuid/"},
                        {"ID":"2",
                        "FSID":"5",
                        "NAME":"test",
                        "SHAREPATH":"/share_fake_uuid_thickfs/"},
                         {"ID":"3",
                        "FSID":"6",
                        "NAME":"test",
                        "SHAREPATH":"/share_fake_uuid_inpartition/"}]}"""
                else:
                    data = """{"error":{"code":0},
                        "data":[{"ID":"1",
                        "FSID":"4",
                        "NAME":"test",
                        "SHAREPATH":"/share_fake_uuid_fail/"}]}"""

            if url == "/CIFSHARE?range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"2",
                    "FSID":"4",
                    "NAME":"test",
                    "SHAREPATH":"/share_fake_uuid/"}]}"""

            if url == "/NFSHARE?range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"1",
                    "FSID":"4",
                    "NAME":"test_fail",
                    "SHAREPATH":"/share_fake_uuid_fail/"}]}"""

            if url == "/CIFSHARE?range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"2",
                    "FSID":"4",
                    "NAME":"test_fail",
                    "SHAREPATH":"/share_fake_uuid_fail/"}]}"""

            if url == "/NFSHARE/1" or url == "/CIFSHARE/2":
                data = """{"error":{"code":0}}"""
                self.delete_flag = True

            if url == "/FSSNAPSHOT":
                data = """{"error":{"code":0},"data":{
                            "ID":"3"}}"""
                self.create_snapflag = True

            if url == "/FSSNAPSHOT/4@share_snapshot_fake_snapshot_uuid":
                if self.snapshot_flag:
                    data = """{"error":{"code":0},"data":{"ID":"3"}}"""
                else:
                    data = '{"error":{"code":1073754118}}'
                self.delete_flag = True

            if url == "/FSSNAPSHOT/3":
                data = """{"error":{"code":0}}"""
                self.delete_flag = True

            if url == "/NFS_SHARE_AUTH_CLIENT":
                data, self.allow_ro_flag, self.allow_rw_flag = \
                    allow_access('NFS', method, data)
                self.allow_flag = True

            if url == "/CIFS_SHARE_AUTH_CLIENT":
                data, self.allow_ro_flag, self.allow_rw_flag = \
                    allow_access('CIFS', method, data)
                self.allow_flag = True

            if url == "/FSSNAPSHOT?TYPE=48&PARENTID=4"\
                      "&&sortby=TIMESTAMP,d&range=[0-2000]":
                data = """{"error":{"code":0},
                "data":[{"ID":"3",
                "NAME":"share_snapshot_fake_snapshot_uuid"}]}"""
                self.delete_flag = True

            if url == "/NFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::1&range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"0",
                    "NAME":"100.112.0.1_fail"}]}"""

            if url == "/CIFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::2&range=[0-100]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"0",
                    "NAME":"user_name_fail"}]}"""

            if url == "/NFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::1&range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"5",
                    "NAME":"100.112.0.1"}]}"""

            if url == "/CIFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::2&range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"6",
                    "NAME":"user_name"}]}"""

            if url == "/NFS_SHARE_AUTH_CLIENT/5"\
                      or url == "/CIFS_SHARE_AUTH_CLIENT/6":
                data = """{"error":{"code":0}}"""
                self.deny_flag = True

            if url == "/NFSHARE/count" or url == "/CIFSHARE/count":
                data = """{"error":{"code":0},"data":{
                            "COUNT":"196"}}"""

            if url == "/NFS_SHARE_AUTH_CLIENT/count?filter=PARENTID::1"\
                      or url == "/CIFS_SHARE_AUTH_CLIENT/count?filter="\
                      "PARENTID::2":
                data = """{"error":{"code":0},"data":{
                            "COUNT":"196"}}"""

            if url == "/CIFSSERVICE":
                if self.service_status_flag:
                    data = """{"error":{"code":0},"data":{
                                "RUNNINGSTATUS":"2"}}"""
                else:
                    data = """{"error":{"code":0},"data":{
                                "RUNNINGSTATUS":"1"}}"""

            if url == "/NFSSERVICE":
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

            if url == "/FILESYSTEM?range=[0-8191]":
                data = """{"error":{"code":0},
                "data":[{"ID":"4",
                "NAME":"share_fake_uuid"}]}"""

            if url == "/filesystem/4":
                data, self.extend_share_flag, self.shrink_share_flag = (
                    filesystem(method, data, self.fs_status_flag))
                self.delete_flag = True

            if url == "/filesystem/5":
                data, self.extend_share_flag, self.shrink_share_flag = (
                    filesystem_thick(method, data, self.fs_status_flag))
                self.delete_flag = True

            if url == "/filesystem/6":
                data, self.extend_share_flag, self.shrink_share_flag = (
                    filesystem_inpartition(method, data, self.fs_status_flag))
                self.delete_flag = True

            if url == "/cachepartition":
                if self.partition_exist:
                    data = """{"error":{"code":0},
                    "data":[{"ID":"7",
                    "NAME":"test_partition_name"}]}"""
                else:
                    data = """{"error":{"code":0},
                    "data":[{"ID":"7",
                    "NAME":"test_partition_name_fail"}]}"""

            if url == "/cachepartition/1":
                if self.partition_exist:
                    data = """{"error":{"code":0},
                    "data":{"ID":"7",
                    "NAME":"test_partition_name"}}"""
                else:
                    data = """{"error":{"code":0},
                    "data":{"ID":"7",
                    "NAME":"test_partition_name_fail"}}"""

            if url == "/SMARTCACHEPARTITION":
                if self.cache_exist:
                    data = """{"error":{"code":0},
                    "data":[{"ID":"8",
                    "NAME":"test_cache_name"}]}"""
                else:
                    data = """{"error":{"code":0},
                    "data":[{"ID":"8",
                    "NAME":"test_cache_name_fail"}]}"""

            if url == "/SMARTCACHEPARTITION/1":
                if self.cache_exist:
                    data = """{"error":{"code":0},
                    "data":{"ID":"8",
                    "NAME":"test_cache_name"}}"""
                else:
                    data = """{"error":{"code":0},
                    "data":{"ID":"8",
                    "NAME":"test_cache_name_fail"}}"""

            if url == "/filesystem/associate/cachepartition":
                data = """{"error":{"code":0}}"""
                self.add_fs_to_partition_flag = True

            if url == "/SMARTCACHEPARTITION/CREATE_ASSOCIATE":
                data = """{"error":{"code":0}}"""
                self.add_fs_to_cache_flag = True

            if url == "/SMARTCACHEPARTITION/REMOVE_ASSOCIATE":
                data = """{"error":{"code":0}}"""

            if url == "/smartPartition/removeFs":
                data = """{"error":{"code":0}}"""
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


@ddt.ddt
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
        self.configuration.max_over_subscription_ratio = 1

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
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid'},
            ],
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'share_type_id': 'fake_id',
        }

        self.share_nfs_thick = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#OpenStack_Pool_Thick',
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid'},
            ],
            'share_type_id': 'fake_id',
        }

        self.share_nfs_thickfs = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid-thickfs',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid_thickfs'},
            ],
            'share_type_id': 'fake_id',
        }

        self.share_nfs_thick_thickfs = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid-thickfs',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#OpenStack_Pool_Thick',
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid_thickfs'},
            ],
            'share_type_id': 'fake_id',
        }

        self.share_nfs_inpartition = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid-inpartition',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid_inpartition'},
            ],
            'share_type_id': 'fake_id',
        }

        self.share_manage_nfs = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-manage-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid'},
            ],
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'share_type_id': 'fake_id',
        }

        self.share_pool_name_not_match = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-manage-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'export_locations': [
                {'path': '100.115.10.68:/share_fake_uuid'},
            ],
            'host': 'fake_host@fake_backend#OpenStack_Pool_not_match',
            'share_type_id': 'fake_id',
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
            'host': 'fake_host@fake_backend#OpenStack_Pool',
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
            'export_locations': [
                {'path': 'share_fake_uuid'},
            ],
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'share_type_id': 'fake_id',
        }

        self.share_manage_cifs = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-manage-uuid',
            'size': 1,
            'share_proto': 'CIFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'export_locations': [
                {'path': '\\\\100.115.10.68\\share_fake_uuid'},
            ],
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'share_type_id': 'fake_id',
        }

        self.nfs_snapshot = {
            'id': 'fake_snapshot_uuid',
            'display_name': 'snapshot',
            'name': 'fake_snapshot_name',
            'size': 1,
            'share_name': 'share_fake_uuid',
            'share': {
                'share_name': 'share_fake_uuid',
                'share_id': 'fake_uuid',
                'share_size': 1,
                'share_proto': 'NFS',
            },
        }

        self.cifs_snapshot = {
            'id': 'fake_snapshot_uuid',
            'display_name': 'snapshot',
            'name': 'fake_snapshot_name',
            'size': 1,
            'share_name': 'share_fake_uuid',
            'share': {
                'share_name': 'share_fake_uuid',
                'share_id': 'fake_uuid',
                'share_size': 1,
                'share_proto': 'CIFS',
            },
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

        self.driver_options = {
            'volume_id': 'fake',
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

        fake_share_type_id_not_extra = 'fake_id'
        self.fake_type_not_extra = {
            'test_with_extra': {
                'created_at': 'fake_time',
                'deleted': '0',
                'deleted_at': None,
                'extra_specs': {},
                'required_extra_specs': {},
                'id': fake_share_type_id_not_extra,
                'name': 'test_with_extra',
                'updated_at': None
            }
        }

        fake_extra_specs = {
            'capabilities:dedupe': '<is> True',
            'capabilities:compression': '<is> True',
            'capabilities:huawei_smartcache': '<is> True',
            'huawei_smartcache:cachename': 'test_cache_name',
            'capabilities:huawei_smartpartition': '<is> True',
            'huawei_smartpartition:partitionname': 'test_partition_name',
            'capabilities:thin_provisioning': '<is> True',
            'test:test:test': 'test',
        }

        fake_share_type_id = 'fooid-2'
        self.fake_type_w_extra = {
            'test_with_extra': {
                'created_at': 'fake_time',
                'deleted': '0',
                'deleted_at': None,
                'extra_specs': fake_extra_specs,
                'required_extra_specs': {},
                'id': fake_share_type_id,
                'name': 'test_with_extra',
                'updated_at': None
            }
        }

        fake_extra_specs = {
            'capabilities:dedupe': '<is> True',
            'capabilities:compression': '<is> True',
            'capabilities:huawei_smartcache': '<is> False',
            'huawei_smartcache:cachename': None,
            'capabilities:huawei_smartpartition': '<is> False',
            'huawei_smartpartition:partitionname': None,
            'capabilities:thin_provisioning': '<is> True',
            'test:test:test': 'test',
        }

        fake_share_type_id = 'fooid-3'
        self.fake_type_fake_extra = {
            'test_with_extra': {
                'created_at': 'fake_time',
                'deleted': '0',
                'deleted_at': None,
                'extra_specs': fake_extra_specs,
                'required_extra_specs': {},
                'id': fake_share_type_id,
                'name': 'test_with_extra',
                'updated_at': None
            }
        }

        fake_extra_specs = {
            'capabilities:dedupe': '<is> True',
            'capabilities:compression': '<is> True',
            'capabilities:huawei_smartcache': '<is> False',
            'huawei_smartcache:cachename': None,
            'capabilities:huawei_smartpartition': '<is> False',
            'huawei_smartpartition:partitionname': None,
            'capabilities:thin_provisioning': '<is> False',
            'test:test:test': 'test',
        }

        fake_share_type_id = 'fooid-4'
        self.fake_type_thin_extra = {
            'test_with_extra': {
                'created_at': 'fake_time',
                'deleted': '0',
                'deleted_at': None,
                'extra_specs': fake_extra_specs,
                'required_extra_specs': {},
                'id': fake_share_type_id,
                'name': 'test_with_extra',
                'updated_at': None
            }
        }

        self.share_nfs_host_not_exist = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#',
        }

        self.share_nfs_storagepool_fail = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#OpenStack_Pool2',
        }

        fake_extra_specs = {
            'driver_handles_share_servers': 'False',
        }
        fake_share_type_id = 'fake_id'
        self.fake_type_extra = {
            'test_with_extra': {
                'created_at': 'fake_time',
                'deleted': '0',
                'deleted_at': None,
                'extra_specs': fake_extra_specs,
                'required_extra_specs': {},
                'id': fake_share_type_id,
                'name': 'test_with_extra',
                'updated_at': None
            }
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

    def test_create_share_storagepool_not_exist(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidHost,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs_host_not_exist,
                          self.share_server)

    def test_create_share_nfs_storagepool_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidHost,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs_storagepool_fail,
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
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_shrink_share_success(self):
        self.driver.plugin.helper.shrink_share_flag = False
        self.driver.plugin.helper.login()
        self.driver.shrink_share(self.share_nfs, 1,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.shrink_share_flag)

    def test_shrink_share_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_normal = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.shrink_share,
                          self.share_nfs,
                          1,
                          self.share_server)

    def test_shrink_share_size_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.shrink_share,
                          self.share_nfs,
                          5,
                          self.share_server)

    def test_shrink_share_alloctype_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.fs_status_flag = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.shrink_share,
                          self.share_nfs,
                          1,
                          self.share_server)

    def test_shrink_share_not_exist(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.share_exist = False
        self.assertRaises(exception.InvalidShare,
                          self.driver.shrink_share,
                          self.share_nfs,
                          1,
                          self.share_server)

    def test_extend_share_success(self):
        self.driver.plugin.helper.extend_share_flag = False
        self.driver.plugin.helper.login()
        self.driver.extend_share(self.share_nfs, 5,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.extend_share_flag)

    def test_extend_share_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidInput,
                          self.driver.extend_share,
                          self.share_nfs,
                          3,
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
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_create_share_cifs_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_cifs,
                                            self.share_server)
        self.assertEqual("\\\\100.115.10.68\\share_fake_uuid", location)

    def test_create_share_with_extra(self):
        self.driver.plugin.helper.add_fs_to_partition_flag = False
        self.driver.plugin.helper.add_fs_to_cache_flag = False
        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)
        self.assertTrue(self.driver.plugin.helper.add_fs_to_partition_flag)
        self.assertTrue(self.driver.plugin.helper.add_fs_to_cache_flag)

    @ddt.data({'capabilities:dedupe': '<is> True',
               'capabilities:thin_provisioning': '<is> False'},
              {'capabilities:dedupe': '<is> True',
               'capabilities:compression': '<is> True',
               'capabilities:thin_provisioning': '<is> False'},
              {'capabilities:huawei_smartcache': '<is> True',
               'huawei_smartcache:cachename': None},
              {'capabilities:huawei_smartpartition': '<is> True',
               'huawei_smartpartition:partitionname': None},
              {'capabilities:huawei_smartcache': '<is> True'},
              {'capabilities:huawei_smartpartition': '<is> True'})
    def test_create_share_with_extra_error(self, fake_extra_specs):
        fake_share_type_id = 'fooid-2'
        fake_type_error_extra = {
            'test_with_extra': {
                'created_at': 'fake_time',
                'deleted': '0',
                'deleted_at': None,
                'extra_specs': fake_extra_specs,
                'required_extra_specs': {},
                'id': fake_share_type_id,
                'name': 'test_with_extra',
                'updated_at': None
            }
        }
        share_type = fake_type_error_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs_thick,
                          self.share_server)

    def test_create_share_cache_not_exist(self):
        self.driver.plugin.helper.cache_exist = False
        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_add_share_to_cache_fail(self):
        opts = dict(
            huawei_smartcache='true',
            cachename=None,
        )
        fsid = 4
        smartcache = smartx.SmartCache(self.driver.plugin.helper)
        self.assertRaises(exception.InvalidInput, smartcache.add,
                          opts, fsid)

    def test_create_share_partition_not_exist(self):
        self.driver.plugin.helper.partition_exist = False
        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def test_add_share_to_partition_fail(self):
        opts = dict(
            huawei_smartpartition='true',
            partitionname=None,
        )
        fsid = 4
        smartpartition = smartx.SmartPartition(self.driver.plugin.helper)
        self.assertRaises(exception.InvalidInput, smartpartition.add,
                          opts, fsid)

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

    def test_get_share_stats_refresh_pool_not_exist(self):
        self.driver.plugin.helper.login()
        self.recreate_fake_conf_file(pool_node_flag=False)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.assertRaises(exception.InvalidInput,
                          self.driver._update_share_stats)

    def test_get_share_stats_refresh(self):
        self.driver.plugin.helper.login()
        self.driver._update_share_stats()

        expected = {}
        expected["share_backend_name"] = "fake_share_backend_name"
        expected["driver_handles_share_servers"] = False
        expected["vendor_name"] = 'Huawei'
        expected["driver_version"] = '1.1'
        expected["storage_protocol"] = 'NFS_CIFS'
        expected['reserved_percentage'] = 0
        expected['total_capacity_gb'] = 0.0
        expected['free_capacity_gb'] = 0.0
        expected['QoS_support'] = False
        expected["snapshot_support"] = False
        expected["pools"] = []
        pool_thin = dict(
            pool_name='OpenStack_Pool',
            total_capacity_gb=2.0,
            free_capacity_gb=1.0,
            allocated_capacity_gb=1.0,
            QoS_support=False,
            reserved_percentage=0,
            compression=True,
            dedupe=True,
            max_over_subscription_ratio=1,
            provisioned_capacity_gb=1.0,
            thin_provisioning=True,
            huawei_smartcache=True,
            huawei_smartpartition=True,
        )
        pool_thick = dict(
            pool_name='OpenStack_Pool_Thick',
            total_capacity_gb=2.0,
            free_capacity_gb=1.0,
            allocated_capacity_gb=1.0,
            QoS_support=False,
            reserved_percentage=0,
            compression=False,
            dedupe=False,
            max_over_subscription_ratio=1,
            provisioned_capacity_gb=1.0,
            thin_provisioning=False,
            huawei_smartcache=True,
            huawei_smartpartition=True,
        )
        expected["pools"].append(pool_thin)
        expected["pools"].append(pool_thick)
        self.assertEqual(expected, self.driver._stats)

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

    @ddt.data("NFS", "CIFS")
    def test_get_share_url_type(self, share_proto):
        share_url_type = self.driver.plugin.helper._get_share_url_type(
            share_proto)
        self.assertEqual(share_proto + 'HARE', share_url_type)

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
        self.assertIsNone(result)

    def test_deny_access_user_proto_fail(self):
        self.driver.plugin.helper.login()
        result = self.driver.deny_access(self._context, self.share_cifs,
                                         self.access_ip, self.share_server)
        self.assertIsNone(result)

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

    @ddt.data({"share_proto": "NFS",
               "path": ["100.115.10.68:/share_fake_manage_uuid"]},
              {"share_proto": "CIFS",
               "path": ["\\\\100.115.10.68\\share_fake_manage_uuid"]})
    @ddt.unpack
    def test_manage_share_nfs_success(self, share_proto, path):
        if share_proto == "NFS":
            share = self.share_manage_nfs
        elif share_proto == "CIFS":
            share = self.share_manage_cifs

        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db, 'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        share_info = self.driver.manage_existing(share,
                                                 self.driver_options)
        self.assertEqual(4, share_info["size"])
        self.assertEqual(path, share_info["export_locations"])

    @ddt.data({"fs_alloctype": "THIN",
               "path": ["100.115.10.68:/share_fake_manage_uuid"]},
              {"fs_alloctype": "THICK",
               "path": ["100.115.10.68:/share_fake_uuid_thickfs"]})
    @ddt.unpack
    def test_manage_share_with_default_type(self, fs_alloctype, path):
        if fs_alloctype == "THIN":
            share = self.share_manage_nfs
        elif fs_alloctype == "THICK":
            share = self.share_nfs_thick_thickfs

        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db, 'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        share_info = self.driver.manage_existing(share,
                                                 self.driver_options)
        self.assertEqual(4, share_info["size"])
        self.assertEqual(path, share_info["export_locations"])

    @ddt.data({"path": ["100.115.10.68:/share_fake_uuid_inpartition"]})
    @ddt.unpack
    def test_manage_share_remove_from_partition(self, path):
        share = self.share_nfs_inpartition

        share_type = self.fake_type_fake_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        share_info = self.driver.manage_existing(share,
                                                 self.driver_options)
        self.assertEqual(4, share_info["size"])
        self.assertEqual(path,
                         share_info["export_locations"])

    @ddt.data({"flag": "share_not_exist", "exc": exception.InvalidShare},
              {"flag": "fs_status_error", "exc": exception.InvalidShare},
              {"flag": "poolname_not_match", "exc": exception.InvalidHost})
    @ddt.unpack
    def test_manage_share_fail(self, flag, exc):
        share = None
        if flag == "share_not_exist":
            self.driver.plugin.helper.share_exist = False
            share = self.share_nfs
        elif flag == "fs_status_error":
            self.driver.plugin.helper.fs_status_flag = False
            share = self.share_nfs
        elif flag == "poolname_not_match":
            share = self.share_pool_name_not_match

        self.driver.plugin.helper.login()
        share_type = self.fake_type_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.assertRaises(exc,
                          self.driver.manage_existing,
                          share,
                          self.driver_options)

    def test_manage_share_thickfs_set_dedupe_fail(self):
        share = self.share_nfs_thick_thickfs

        self.driver.plugin.helper.login()
        share_type = self.fake_type_thin_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidInput,
                          self.driver.manage_existing,
                          share,
                          self.driver_options)

    def test_manage_share_thickfs_not_match_thinpool_fail(self):
        share = self.share_nfs_thickfs

        self.driver.plugin.helper.login()
        share_type = self.fake_type_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidHost,
                          self.driver.manage_existing,
                          share,
                          self.driver_options)

    @ddt.data({"flag": "old_cache_id", "exc": exception.InvalidInput},
              {"flag": "not_old_cache_id", "exc": exception.InvalidInput})
    @ddt.unpack
    def test_manage_share_cache_not_exist(self, flag, exc):
        share = None
        if flag == "old_cache_id":
            share = self.share_nfs_inpartition
        elif flag == "not_old_cache_id":
            share = self.share_nfs

        self.driver.plugin.helper.cache_exist = False
        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.assertRaises(exc,
                          self.driver.manage_existing,
                          share,
                          self.share_server)

    def test_manage_add_share_to_cache_fail(self):
        opts = dict(
            huawei_smartcache='true',
            huawei_smartpartition='true',
            cachename='test_cache_name_fake',
            partitionname='test_partition_name_fake',
        )
        fs = dict(
            SMARTCACHEID='6',
            SMARTPARTITIONID=None,
        )
        poolinfo = dict(
            type='Thin',
        )
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_retype_change_opts,
                          opts, poolinfo, fs)

    def test_manage_notsetcache_fail(self):
        opts = dict(
            huawei_smartcache='true',
            huawei_smartpartition='true',
            cachename=None,
            partitionname='test_partition_name_fake',
        )
        fs = dict(
            SMARTCACHEID='6',
            SMARTPARTITIONID='6',
        )
        poolinfo = dict(
            type='Thin',
        )
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_retype_change_opts,
                          opts, poolinfo, fs)

    @ddt.data({"flag": "old_partition_id", "exc": exception.InvalidInput},
              {"flag": "not_old_partition_id", "exc": exception.InvalidInput})
    @ddt.unpack
    def test_manage_share_partition_not_exist(self, flag, exc):
        share = None
        if flag == "old_partition_id":
            share = self.share_nfs_inpartition
        elif flag == "not_old_partition_id":
            share = self.share_nfs

        self.driver.plugin.helper.partition_exist = False
        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.assertRaises(exc,
                          self.driver.manage_existing,
                          share,
                          self.share_server)

    def test_manage_add_share_to_partition_fail(self):
        opts = dict(
            huawei_smartcache='true',
            huawei_smartpartition='true',
            cachename='test_cache_name_fake',
            partitionname='test_partition_name_fake',
        )
        fs = dict(
            SMARTCACHEID=None,
            SMARTPARTITIONID='6',
        )
        poolinfo = dict(
            type='Thin',
        )
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_retype_change_opts,
                          opts, poolinfo, fs)

    def test_manage_notset_partition_fail(self):
        opts = dict(
            huawei_smartcache='true',
            huawei_smartpartition='true',
            cachename='test_cache_name_fake',
            partitionname=None,
        )
        fs = dict(
            SMARTCACHEID=None,
            SMARTPARTITIONID='6',
        )
        poolinfo = dict(
            type='Thin',
        )
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_retype_change_opts,
                          opts, poolinfo, fs)

    @ddt.data({"share_proto": "NFS",
               "export_path": "fake_ip:/share_fake_uuid"},
              {"share_proto": "NFS", "export_path": "fake_ip:/"},
              {"share_proto": "NFS",
               "export_path": "100.112.0.1://share_fake_uuid"},
              {"share_proto": "NFS", "export_path": None},
              {"share_proto": "NFS", "export_path": "\\share_fake_uuid"},
              {"share_proto": "CIFS",
               "export_path": "\\\\fake_ip\\share_fake_uuid"},
              {"share_proto": "CIFS",
               "export_path": "\\dd\\100.115.10.68\\share_fake_uuid"})
    @ddt.unpack
    def test_manage_export_path_fail(self, share_proto, export_path):
        share_manage_nfs_export_path_fail = {
            'id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-manage-uuid',
            'size': 1,
            'share_proto': share_proto,
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'export_locations': [
                {'path': export_path},
            ],
            'host': 'fake_host@fake_backend#OpenStack_Pool',
            'share_type_id': 'fake_id'
        }
        share_type = self.fake_type_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidInput,
                          self.driver.manage_existing,
                          share_manage_nfs_export_path_fail,
                          self.driver_options)

    def test_manage_logical_port_ip_fail(self):
        self.recreate_fake_conf_file(logical_port_ip="")
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        share_type = self.fake_type_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.assertRaises(exception.InvalidInput,
                          self.driver.manage_existing,
                          self.share_nfs,
                          self.driver_options)

    def test_get_pool_success(self):
        self.driver.plugin.helper.login()
        pool_name = self.driver.get_pool(self.share_nfs_host_not_exist)
        self.assertEqual('OpenStack_Pool', pool_name)

    def test_get_pool_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.share_exist = False
        pool_name = self.driver.get_pool(self.share_nfs_host_not_exist)
        self.assertIsNone(pool_name)

    def test_multi_resturls_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.recreate_fake_conf_file(multi_url=True)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_multi_url_flag = 2
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_multi_resturls_fail(self):
        self.recreate_fake_conf_file(multi_url=True)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.test_multi_url_flag = 1
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

    def create_fake_conf_file(self, fake_conf_file,
                              product_flag=True, username_flag=True,
                              pool_node_flag=True, timeout_flag=True,
                              wait_interval_flag=True,
                              multi_url=False,
                              logical_port_ip='100.115.10.68'):
        doc = xml.dom.minidom.Document()
        config = doc.createElement('Config')
        doc.appendChild(config)

        storage = doc.createElement('Storage')
        config.appendChild(storage)

        controllerip0 = doc.createElement('LogicalPortIP')
        controllerip0_text = doc.createTextNode(logical_port_ip)
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
        if multi_url:
            url_text = doc.createTextNode('http://100.115.10.69:8082/'
                                          'deviceManager/rest/;'
                                          'http://100.115.10.70:8082/'
                                          'deviceManager/rest/')
        else:
            url_text = doc.createTextNode('http://100.115.10.69:8082/'
                                          'deviceManager/rest/')
        url.appendChild(url_text)
        storage.appendChild(url)

        lun = doc.createElement('Filesystem')
        config.appendChild(lun)

        thin_storagepool = doc.createElement('Thin_StoragePool')
        if pool_node_flag:
            pool_text = doc.createTextNode('OpenStack_Pool;OpenStack_Pool2; ;')
        else:
            pool_text = doc.createTextNode('')
        thin_storagepool.appendChild(pool_text)

        thick_storagepool = doc.createElement('Thick_StoragePool')
        if pool_node_flag:
            pool_text = doc.createTextNode('OpenStack_Pool_Thick')
        else:
            pool_text = doc.createTextNode('')
        thick_storagepool.appendChild(pool_text)

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

        lun.appendChild(timeout)
        lun.appendChild(waitinterval)
        lun.appendChild(thin_storagepool)
        lun.appendChild(thick_storagepool)

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
                                multi_url=False,
                                logical_port_ip='100.115.10.68'):
        self.tmp_dir = tempfile.mkdtemp()
        self.fake_conf_file = self.tmp_dir + '/manila_huawei_conf.xml'
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.create_fake_conf_file(self.fake_conf_file, product_flag,
                                   username_flag, pool_node_flag,
                                   timeout_flag, wait_interval_flag,
                                   multi_url,
                                   logical_port_ip)
        self.addCleanup(os.remove, self.fake_conf_file)
