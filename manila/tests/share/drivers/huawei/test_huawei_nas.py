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
from manila.data import utils as data_utils
from manila import db
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.huawei import constants
from manila.share.drivers.huawei import huawei_nas
from manila.share.drivers.huawei.v3 import connection
from manila.share.drivers.huawei.v3 import helper
from manila.share.drivers.huawei.v3 import smartx
from manila import test
from manila import utils


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
        elif data == """{"IOPRIORITY": "3"}""":
            data = """{"error":{"code":0}}"""
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
                "SMARTCACHEPARTITIONID":"",
                "IOCLASSID":"11"}}"""
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
                    "SMARTCACHEPARTITIONID":"",
                    "IOCLASSID":"11"}}"""
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
                "SMARTCACHEPARTITIONID":"",
                "IOCLASSID":"11"}}"""
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
                    "SMARTCACHEPARTITIONID":"",
                    "IOCLASSID":"11"}}"""
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
                "SMARTCACHEPARTITIONID":"1",
                "IOCLASSID":"11"}}"""
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
                    "SMARTCACHEPARTITIONID":"1",
                    "IOCLASSID":"11"}}"""
    else:
        data = '{"error":{"code":31755596}}'
    return (data, extend_share_flag, shrink_share_flag)


def allow_access(type, method, data):
    allow_ro_flag = False
    allow_rw_flag = False
    request_data = jsonutils.loads(data)
    success_data = """{"error":{"code":0}}"""
    fail_data = """{"error":{"code":1077939723}}"""
    ret = None

    if type == "NFS":
        if request_data['ACCESSVAL'] == '0':
            allow_ro_flag = True
            ret = success_data
        elif request_data['ACCESSVAL'] == '1':
            allow_rw_flag = True
            ret = success_data
    elif type == "CIFS":
        if request_data['PERMISSION'] == '0':
            allow_ro_flag = True
            ret = success_data
        elif request_data['PERMISSION'] == '1':
            allow_rw_flag = True
            ret = success_data
    # Group name should start with '@'.
    if ('group' in request_data['NAME']
            and not request_data['NAME'].startswith('@')):
        ret = fail_data

    if ret is None:
        ret = fail_data
    return (ret, allow_ro_flag, allow_rw_flag)


def dec_driver_handles_share_servers(func):
    def wrapper(*args, **kw):
        self = args[0]
        self.configuration.driver_handles_share_servers = True
        self.recreate_fake_conf_file(logical_port='CTE0.A.H0')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        return func(*args, **kw)
    return wrapper


def QoS_response(method):
    if method == "GET":
        data = """{"error":{"code":0},
                    "data":{"NAME": "OpenStack_Fake_QoS", "MAXIOPS": "100",
                    "FSLIST": "4", "LUNLIST": "", "RUNNINGSTATUS": "2"}}"""
    elif method == "PUT":
        data = """{"error":{"code":0}}"""
    else:
        data = """{"error":{"code":0},
                    "data":{"ID": "11"}}"""
    return data


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
        self.alloc_type = None

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
                request_data = jsonutils.loads(data)
                self.alloc_type = request_data.get('ALLOCTYPE')
                data = """{"error":{"code":0},"data":{
                            "ID":"4"}}"""

            if url == "/system/":
                data = """{"error":{"code":0},
                    "data":{"PRODUCTVERSION": "V300R003C10"}}"""

            if url == "/ioclass" or url == "/ioclass/11":
                data = QoS_response(method)

            if url == "/ioclass/active/11":
                data = """{"error":{"code":0},
                    "data":[{"ID": "11", "MAXIOPS": "100",
                    "FSLIST": ""}]}"""

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
                    "NAME":"100.112.0.2"}]}"""

            if url == "/CIFS_SHARE_AUTH_CLIENT?"\
                      "filter=PARENTID::2&range=[100-200]":
                data = """{"error":{"code":0},
                    "data":[{"ID":"6",
                    "NAME":"user_exist"}]}"""

            if url in ("/NFS_SHARE_AUTH_CLIENT/0",
                       "/NFS_SHARE_AUTH_CLIENT/5",
                       "/CIFS_SHARE_AUTH_CLIENT/0",
                       "/CIFS_SHARE_AUTH_CLIENT/6"):
                if method == "DELETE":
                    data = """{"error":{"code":0}}"""
                    self.deny_flag = True
                elif method == "GET":
                    if 'CIFS' in url:
                        data = """{"error":{"code":0},
                            "data":{"'PERMISSION'":"0"}}"""
                    else:
                        data = """{"error":{"code":0},
                            "data":{"ACCESSVAL":"0"}}"""
                else:
                    data = """{"error":{"code":0}}"""
                    self.allow_rw_flagg = True

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

            if url == "/ETH_PORT":
                data = """{"error":{"code":0},
                    "data":[{"ID": "4",
                    "LOCATION":"CTE0.A.H0",
                    "IPV4ADDR":"",
                    "BONDNAME":"",
                    "BONDID":"",
                    "RUNNINGSTATUS":"10"},
                    {"ID": "6",
                    "LOCATION":"CTE0.A.H1",
                    "IPV4ADDR":"",
                    "BONDNAME":"fake_bond",
                    "BONDID":"5",
                    "RUNNINGSTATUS":"10"}]}"""

            if url == "/ETH_PORT/6":
                data = """{"error":{"code":0},
                    "data":{"ID": "6",
                    "LOCATION":"CTE0.A.H1",
                    "IPV4ADDR":"",
                    "BONDNAME":"fake_bond",
                    "BONDID":"5",
                    "RUNNINGSTATUS":"10"}}"""

            if url == "/BOND_PORT":
                data = "{\"error\":{\"code\":0},\
                      \"data\":[{\"ID\": \"5\",\
                      \"NAME\":\"fake_bond\",\
                      \"PORTIDLIST\": \"[\\\"6\\\"]\",\
                      \"RUNNINGSTATUS\":\"10\"}]}"

            if url == "/vlan":
                if method == "GET":
                    data = """{"error":{"code":0}}"""
                else:
                    data = """{"error":{"code":0},"data":{
                        "ID":"4"}}"""

            if url == "/LIF":
                if method == "GET":
                    data = """{"error":{"code":0}}"""
                else:
                    data = """{"error":{"code":0},"data":{
                        "ID":"4"}}"""

            if url == "/DNS_Server":
                if method == "GET":
                    data = "{\"error\":{\"code\":0},\"data\":{\
                         \"ADDRESS\":\"[\\\"\\\"]\"}}"
                else:
                    data = """{"error":{"code":0}}"""

            if url == "/AD_CONFIG":
                if method == "GET":
                    data = """{"error":{"code":0},"data":{
                        "DOMAINSTATUS":"1",
                        "FULLDOMAINNAME":"huawei.com"}}"""
                else:
                    data = """{"error":{"code":0}}"""

            if url == "/LDAP_CONFIG":
                if method == "GET":
                    data = """{"error":{"code":0},"data":{
                        "BASEDN":"dc=huawei,dc=com",
                        "LDAPSERVER": "100.97.5.87"}}"""
                else:
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

        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self.configuration = mock.Mock(spec=conf.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.network_config_group = 'fake_network_config_group'
        self.configuration.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.configuration.share_backend_name = 'fake_share_backend_name'
        self.configuration.huawei_share_backend = 'V3'
        self.configuration.max_over_subscription_ratio = 1
        self.configuration.driver_handles_share_servers = False
        self.configuration.replication_domain = None

        self.tmp_dir = tempfile.mkdtemp()
        self.fake_conf_file = self.tmp_dir + '/manila_huawei_conf.xml'
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.create_fake_conf_file(self.fake_conf_file)
        self.addCleanup(os.remove, self.fake_conf_file)

        self.configuration.manila_huawei_conf_file = self.fake_conf_file
        self._helper_fake = mock.Mock()
        self.mock_object(huawei_nas.importutils, 'import_object',
                         mock.Mock(return_value=self._helper_fake))

        self.mock_object(time, 'sleep', fake_sleep)
        self.driver = FakeHuaweiNasDriver(configuration=self.configuration)
        self.driver.plugin.helper.test_normal = True

        self.share_nfs = {
            'id': 'fake_uuid',
            'share_id': 'fake_uuid',
            'project_id': 'fake_tenant_id',
            'display_name': 'fake',
            'name': 'share-fake-uuid',
            'size': 1,
            'share_proto': 'NFS',
            'share_network_id': 'fake_net_id',
            'share_server_id': 'fake-share-srv-id',
            'host': 'fake_host@fake_backend#OpenStack_Pool',
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
            'share_id': 'fake_uuid',
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
            'snapshot_id': 'fake_snapshot_uuid',
            'display_name': 'snapshot',
            'name': 'fake_snapshot_name',
            'size': 1,
            'share_name': 'share_fake_uuid',
            'share_id': 'fake_uuid',
            'share': {
                'share_name': 'share_fake_uuid',
                'share_id': 'fake_uuid',
                'share_size': 1,
                'share_proto': 'NFS',
            },
        }

        self.cifs_snapshot = {
            'id': 'fake_snapshot_uuid',
            'snapshot_id': 'fake_snapshot_uuid',
            'display_name': 'snapshot',
            'name': 'fake_snapshot_name',
            'size': 1,
            'share_name': 'share_fake_uuid',
            'share_id': 'fake_uuid',
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

        self.access_ip_exist = {
            'access_type': 'ip',
            'access_to': '100.112.0.2',
            'access_level': 'rw',
        }

        self.access_user = {
            'access_type': 'user',
            'access_to': 'user_name',
            'access_level': 'rw',
        }

        self.access_user_exist = {
            'access_type': 'user',
            'access_to': 'user_exist',
            'access_level': 'rw',
        }

        self.access_group = {
            'access_type': 'user',
            'access_to': 'group_name',
            'access_level': 'rw',
        }

        self.access_cert = {
            'access_type': 'cert',
            'access_to': 'fake_cert',
            'access_level': 'rw',
        }

        self.driver_options = {
            'volume_id': 'fake',
        }
        self.share_server = None
        self.driver._licenses = ['fake']

        self.fake_network_allocations = [{
            'id': 'fake_network_allocation_id',
            'ip_address': '111.111.111.109',
        }]
        self.fake_network_info = {
            'server_id': '0',
            'segmentation_id': '2',
            'cidr': '111.111.111.0/24',
            'neutron_net_id': 'fake_neutron_net_id',
            'neutron_subnet_id': 'fake_neutron_subnet_id',
            'nova_net_id': '',
            'security_services': '',
            'network_allocations': self.fake_network_allocations,
            'network_type': 'vlan',
        }
        self.fake_active_directory = {
            'type': 'active_directory',
            'dns_ip': '100.97.5.5',
            'user': 'ad_user',
            'password': 'ad_password',
            'domain': 'huawei.com'
        }
        self.fake_ldap = {
            'type': 'ldap',
            'server': '100.97.5.87',
            'domain': 'dc=huawei,dc=com'
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

    def _get_share_by_proto(self, share_proto):
        if share_proto == "NFS":
            share = self.share_nfs
        elif share_proto == "CIFS":
            share = self.share_cifs
        else:
            share = None
        return share

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

    def test_conf_logical_ip_fail(self):
        self.configuration.driver_handles_share_servers = True
        self.recreate_fake_conf_file(logical_port="fake_port")
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.configuration.driver_handles_share_servers = False
        self.assertRaises(exception.InvalidInput,
                          self.driver.plugin.check_conf_file)

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

    def test_create_share_alloctype_fail(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.recreate_fake_conf_file(alloctype_value='alloctype_fail')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
                          self.share_server)

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

    def test_create_share_alloctype_thin_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.recreate_fake_conf_file(alloctype_value='Thin')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)
        self.assertEqual(constants.ALLOC_TYPE_THIN_FLAG,
                         self.driver.plugin.helper.alloc_type)

    def test_create_share_alloctype_thick_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.recreate_fake_conf_file(alloctype_value='Thick')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)
        self.assertEqual(constants.ALLOC_TYPE_THICK_FLAG,
                         self.driver.plugin.helper.alloc_type)

    def test_create_share_no_alloctype_no_extra(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        self.recreate_fake_conf_file(alloctype_value=None)
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)
        self.assertEqual(constants.ALLOC_TYPE_THICK_FLAG,
                         self.driver.plugin.helper.alloc_type)

    def test_create_share_with_extra_thin(self):
        share_type = {
            'extra_specs': {
                'capabilities:thin_provisioning': '<is> True'
            },
        }
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)
        self.assertEqual(constants.ALLOC_TYPE_THIN_FLAG,
                         self.driver.plugin.helper.alloc_type)

    def test_create_share_with_extra_thick(self):
        share_type = {
            'extra_specs': {
                'capabilities:thin_provisioning': '<is> False'
            },
        }
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.driver.plugin.helper.login()
        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)
        self.assertEqual(constants.ALLOC_TYPE_THICK_FLAG,
                         self.driver.plugin.helper.alloc_type)

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
        self.recreate_fake_conf_file(alloctype_value='Thin')
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

    @ddt.data({"fake_extra_specs_qos": {"qos:maxIOPS": "100",
                                        "qos:maxBandWidth": "50",
                                        "qos:IOType": "0"},
               "fake_qos_info": {"MAXIOPS": "100",
                                 "MAXBANDWIDTH": "50",
                                 "IOTYPE": "0",
                                 "LATENCY": "0",
                                 "NAME": "OpenStack_fake_qos"}},
              {"fake_extra_specs_qos": {"qos:maxIOPS": "100",
                                        "qos:IOType": "1"},
               "fake_qos_info": {"NAME": "fake_qos",
                                 "MAXIOPS": "100",
                                 "IOTYPE": "1",
                                 "LATENCY": "0"}},
              {"fake_extra_specs_qos": {"qos:minIOPS": "100",
                                        "qos:minBandWidth": "50",
                                        'qos:latency': "50",
                                        "qos:IOType": "0"},
               "fake_qos_info": {"MINIOPS": "100",
                                 "MINBANDWIDTH": "50",
                                 "IOTYPE": "0",
                                 "LATENCY": "50",
                                 "NAME": "OpenStack_fake_qos"}})
    @ddt.unpack
    def test_create_share_with_qos(self, fake_extra_specs_qos, fake_qos_info):
        fake_share_type_id = 'fooid-2'
        fake_extra_specs = {"capabilities:qos": "<is> True"}
        fake_extra_specs.update(fake_extra_specs_qos)

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

        fake_qos_info_respons = {
            "error": {
                "code": 0
            },
            "data": [{
                "ID": "11",
                "FSLIST": u'["1", "2", "3", "4"]',
                "LUNLIST": '[""]',
                "RUNNINGSTATUS": "2",
            }]
        }

        fake_qos_info_respons["data"][0].update(fake_qos_info)
        share_type = fake_type_error_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(helper.RestHelper,
                         'get_qos',
                         mock.Mock(return_value=fake_qos_info_respons))

        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()

        location = self.driver.create_share(self._context, self.share_nfs,
                                            self.share_server)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    @ddt.data({'capabilities:qos': '<is> True',
               'qos:maxIOPS': -1},
              {'capabilities:qos': '<is> True',
               'qos:IOTYPE': 4},
              {'capabilities:qos': '<is> True',
               'qos:IOTYPE': 100},
              {'capabilities:qos': '<is> True',
               'qos:maxIOPS': 0},
              {'capabilities:qos': '<is> True',
               'qos:minIOPS': 0},
              {'capabilities:qos': '<is> True',
               'qos:minBandWidth': 0},
              {'capabilities:qos': '<is> True',
               'qos:maxBandWidth': 0},
              {'capabilities:qos': '<is> True',
               'qos:latency': 0},
              {'capabilities:qos': '<is> True',
               'qos:maxIOPS': 100},
              {'capabilities:qos': '<is> True',
               'qos:maxIOPS': 100,
               'qos:minBandWidth': 100,
               'qos:IOType': '0'})
    def test_create_share_with_invalid_qos(self, fake_extra_specs):
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

        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share,
                          self._context,
                          self.share_nfs,
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

    @ddt.data({"share_proto": "NFS",
               "fake_qos_info_respons": {"ID": "11", "MAXIOPS": "100",
                                         "IOType": "2",
                                         "FSLIST": u'["0", "1", "4"]'}},
              {"share_proto": "CIFS",
               "fake_qos_info_respons": {"ID": "11", "MAXIOPS": "100",
                                         "IOType": "2", "FSLIST": u'["4"]',
                                         "RUNNINGSTATUS": "2"}})
    @ddt.unpack
    def test_delete_share_success(self, share_proto, fake_qos_info_respons):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        if share_proto == 'NFS':
            share = self.share_nfs
        else:
            share = self.share_cifs
        with mock.patch.object(helper.RestHelper, 'get_qos_info',
                               return_value=fake_qos_info_respons):
            self.driver.delete_share(self._context,
                                     share, self.share_server)
            self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_delete_share_withoutqos_success(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.delete_flag = False
        self.driver.plugin.qos_support = True
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
        self.driver.plugin.helper.delete_flag = False

        fake_qos_info_respons = {
            "ID": "11",
            "FSLIST": u'["1", "2", "3", "4"]',
            "LUNLIST": '[""]',
            "RUNNINGSTATUS": "2",
        }

        self.mock_object(helper.RestHelper,
                         'get_qos_info',
                         mock.Mock(return_value=fake_qos_info_respons))
        self.driver.plugin.helper.login()
        self.driver.delete_share(self._context, self.share_cifs,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.delete_flag)

    def test_get_network_allocations_number_dhss_true(self):
        self.configuration.driver_handles_share_servers = True
        number = self.driver.get_network_allocations_number()
        self.assertEqual(1, number)

    def test_get_network_allocations_number_dhss_false(self):
        self.configuration.driver_handles_share_servers = False
        number = self.driver.get_network_allocations_number()
        self.assertEqual(0, number)

    def test_create_nfsshare_from_nfssnapshot_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin,
                         'copy_snapshot_data',
                         mock.Mock(return_value=True))
        self.mock_object(self.driver.plugin,
                         'umount_share_from_host',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        location = self.driver.create_share_from_snapshot(self._context,
                                                          self.share_nfs,
                                                          self.nfs_snapshot,
                                                          self.share_server)

        self.assertTrue(db.share_type_get.called)
        self.assertEqual(2, self.driver.plugin.
                         mount_share_to_host.call_count)
        self.assertTrue(self.driver.plugin.
                        copy_snapshot_data.called)
        self.assertEqual(2, self.driver.plugin.
                         umount_share_from_host.call_count)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_create_cifsshare_from_cifssnapshot_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin,
                         'copy_snapshot_data',
                         mock.Mock(return_value=True))
        self.mock_object(self.driver.plugin,
                         'umount_share_from_host',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        location = self.driver.create_share_from_snapshot(self._context,
                                                          self.share_cifs,
                                                          self.cifs_snapshot,
                                                          self.share_server)

        self.assertTrue(db.share_type_get.called)
        self.assertEqual(2, self.driver.plugin.
                         mount_share_to_host.call_count)
        self.assertTrue(self.driver.plugin.
                        copy_snapshot_data.called)
        self.assertEqual(2, self.driver.plugin.
                         umount_share_from_host.call_count)
        self.assertEqual("\\\\100.115.10.68\\share_fake_uuid", location)

    def test_create_nfsshare_from_cifssnapshot_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         '_get_access_id',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin,
                         'copy_snapshot_data',
                         mock.Mock(return_value=True))
        self.mock_object(self.driver.plugin,
                         'umount_share_from_host',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.access_id = None
        self.driver.plugin.helper.snapshot_flag = True

        location = self.driver.create_share_from_snapshot(self._context,
                                                          self.share_nfs,
                                                          self.cifs_snapshot,
                                                          self.share_server)

        self.assertTrue(db.share_type_get.called)
        self.assertTrue(self.driver.plugin.
                        _get_access_id.called)
        self.assertEqual(2, self.driver.plugin.
                         mount_share_to_host.call_count)
        self.assertTrue(self.driver.plugin.
                        copy_snapshot_data.called)
        self.assertEqual(2, self.driver.plugin.
                         umount_share_from_host.call_count)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

    def test_create_cifsshare_from_nfssnapshot_success(self):
        share_type = self.fake_type_not_extra['test_with_extra']

        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         '_get_access_id',
                         mock.Mock(return_value={}))
        self.mock_object(utils,
                         'execute',
                         mock.Mock(return_value=("", "")))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        location = self.driver.create_share_from_snapshot(self._context,
                                                          self.share_cifs,
                                                          self.nfs_snapshot,
                                                          self.share_server)

        self.assertTrue(db.share_type_get.called)
        self.assertTrue(self.driver.plugin.
                        _get_access_id.called)
        self.assertEqual(7, utils.execute.call_count)
        self.assertEqual("\\\\100.115.10.68\\share_fake_uuid", location)

    def test_create_share_from_snapshot_nonefs(self):
        self.driver.plugin.helper.login()
        self.mock_object(self.driver.plugin.helper,
                         '_get_fsid_by_name',
                         mock.Mock(return_value={}))
        self.assertRaises(exception.StorageResourceNotFound,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(self.driver.plugin.helper.
                        _get_fsid_by_name.called)

    def test_create_share_from_notexistingsnapshot_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = False
        self.assertRaises(exception.ShareSnapshotNotFound,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)

    def test_create_share_from_share_fail(self):
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True
        self.mock_object(self.driver.plugin,
                         'check_fs_status',
                         mock.Mock(return_value={}))
        self.assertRaises(exception.StorageResourceException,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(self.driver.plugin.check_fs_status.called)

    def test_create_share_from_snapshot_share_error(self):
        self.mock_object(self.driver.plugin,
                         '_get_share_proto',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True
        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(self.driver.plugin.
                        _get_share_proto.called)

    def test_create_share_from_snapshot_allow_oldaccess_fail(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         '_get_share_proto',
                         mock.Mock(return_value='NFS'))
        self.mock_object(self.driver.plugin,
                         '_get_access_id',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin.helper,
                         '_get_share_by_name',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(db.share_type_get.called)
        self.assertTrue(self.driver.plugin._get_share_proto.called)
        self.assertTrue(self.driver.plugin._get_access_id.called)
        self.assertTrue(self.driver.plugin.helper._get_share_by_name.called)

    def test_create_share_from_snapshot_mountshare_fail(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(side_effect=exception.
                                   ShareMountException('err')))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        self.assertRaises(exception.ShareMountException,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(db.share_type_get.called)
        self.assertEqual(1, self.driver.plugin.
                         mount_share_to_host.call_count)

    def test_create_share_from_snapshot_allow_newaccess_fail(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         '_get_share_proto',
                         mock.Mock(return_value='NFS'))
        self.mock_object(self.driver.plugin,
                         '_get_access_id',
                         mock.Mock(return_value='5'))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin.helper,
                         '_get_share_by_name',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin,
                         'umount_share_from_host',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(db.share_type_get.called)
        self.assertTrue(self.driver.plugin._get_share_proto.called)
        self.assertTrue(self.driver.plugin._get_access_id.called)
        self.assertEqual(1, self.driver.plugin.
                         mount_share_to_host.call_count)
        self.assertTrue(self.driver.plugin.helper.
                        _get_share_by_name.called)
        self.assertEqual(1, self.driver.plugin.
                         umount_share_from_host.call_count)

    def test_create_nfsshare_from_nfssnapshot_copydata_fail(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(return_value={}))
        self.mock_object(data_utils,
                         'Copy',
                         mock.Mock(side_effect=Exception('err')))
        self.mock_object(utils,
                         'execute',
                         mock.Mock(return_value={}))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        self.assertRaises(exception.ShareCopyDataException,
                          self.driver.create_share_from_snapshot,
                          self._context, self.share_nfs,
                          self.nfs_snapshot, self.share_server)
        self.assertTrue(db.share_type_get.called)
        self.assertEqual(2, self.driver.plugin.
                         mount_share_to_host.call_count)
        self.assertTrue(data_utils.Copy.called)
        self.assertEqual(2, utils.execute.call_count)

    def test_create_nfsshare_from_nfssnapshot_umountshare_fail(self):
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        self.mock_object(self.driver.plugin,
                         'mount_share_to_host',
                         mock.Mock(return_value={}))
        self.mock_object(self.driver.plugin,
                         'copy_snapshot_data',
                         mock.Mock(return_value=True))
        self.mock_object(self.driver.plugin,
                         'umount_share_from_host',
                         mock.Mock(side_effect=exception.
                                   ShareUmountException('err')))
        self.mock_object(os, 'rmdir',
                         mock.Mock(side_effect=Exception('err')))
        self.driver.plugin.helper.login()
        self.driver.plugin.helper.snapshot_flag = True

        location = self.driver.create_share_from_snapshot(self._context,
                                                          self.share_nfs,
                                                          self.cifs_snapshot,
                                                          self.share_server)

        self.assertTrue(db.share_type_get.called)
        self.assertEqual(2, self.driver.plugin.
                         mount_share_to_host.call_count)
        self.assertTrue(self.driver.plugin.copy_snapshot_data.called)
        self.assertEqual(2, self.driver.plugin.
                         umount_share_from_host.call_count)
        self.assertTrue(os.rmdir.called)
        self.assertEqual("100.115.10.68:/share_fake_uuid", location)

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
        expected["driver_version"] = '1.2'
        expected["storage_protocol"] = 'NFS_CIFS'
        expected['reserved_percentage'] = 0
        expected['total_capacity_gb'] = 0.0
        expected['free_capacity_gb'] = 0.0
        expected['qos'] = True
        expected["snapshot_support"] = True
        expected['replication_domain'] = None
        expected["pools"] = []
        pool = dict(
            pool_name='OpenStack_Pool',
            total_capacity_gb=2.0,
            free_capacity_gb=1.0,
            allocated_capacity_gb=1.0,
            qos=True,
            reserved_percentage=0,
            compression=[True, False],
            dedupe=[True, False],
            max_over_subscription_ratio=1,
            provisioned_capacity_gb=1.0,
            thin_provisioning=[True, False],
            huawei_smartcache=[True, False],
            huawei_smartpartition=[True, False],
        )
        expected["pools"].append(pool)
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

    def test_allow_access_nfs_user_success(self):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        self.driver.allow_access(self._context,
                                 self.share_nfs,
                                 self.access_user,
                                 self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)

    @ddt.data(
        {
            'access_type': 'user',
            'access_to': 'user_name',
            'access_level': 'rw',
        },
        {
            'access_type': 'user',
            'access_to': 'group_name',
            'access_level': 'rw',
        },
        {
            'access_type': 'user',
            'access_to': 'domain\\user_name',
            'access_level': 'rw',
        },
        {
            'access_type': 'user',
            'access_to': 'domain\\group_name',
            'access_level': 'rw',
        },
    )
    def test_allow_access_cifs_rw_success(self, access_user):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        self.driver.allow_access(self._context, self.share_cifs,
                                 access_user, self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)

    def test_allow_access_cifs_user_ro_success(self):
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

    def test_update_access_add_delete(self):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        self.deny_flag = False
        add_rules = [self.access_ip]
        delete_rules = [self.access_ip_exist]
        self.driver.update_access(self._context,
                                  self.share_nfs,
                                  None,
                                  add_rules,
                                  delete_rules,
                                  self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)
        self.assertTrue(self.driver.plugin.helper.deny_flag)

    def test_update_access_nfs(self):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        rules = [self.access_ip, self.access_ip_exist]
        self.driver.update_access(self._context,
                                  self.share_nfs,
                                  rules,
                                  None,
                                  None,
                                  self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)

    def test_update_access_cifs(self):
        self.driver.plugin.helper.login()
        self.allow_flag = False
        self.allow_rw_flag = False
        rules = [self.access_user, self.access_user_exist]
        self.driver.update_access(self._context,
                                  self.share_cifs,
                                  rules,
                                  None,
                                  None,
                                  self.share_server)
        self.assertTrue(self.driver.plugin.helper.allow_flag)
        self.assertTrue(self.driver.plugin.helper.allow_rw_flag)

    def test_update_access_rules_share_not_exist(self):
        self.driver.plugin.helper.login()
        rules = [self.access_ip]
        self.driver.plugin.helper.share_exist = False
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.update_access, self._context,
                          self.share_nfs, rules, None, None, self.share_server)

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

    def test_allow_access_nfs_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.allow_access, self._context,
                          self.share_nfs, self.access_cert, self.share_server)

    def test_allow_access_cifs_fail(self):
        self.driver.plugin.helper.login()
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.allow_access, self._context,
                          self.share_cifs, self.access_ip, self.share_server)

    def test_deny_access_nfs_fail(self):
        self.driver.plugin.helper.login()
        result = self.driver.deny_access(self._context, self.share_nfs,
                                         self.access_cert, self.share_server)
        self.assertIsNone(result)

    def test_deny_access_not_exist_fail(self):
        self.driver.plugin.helper.login()
        access_ip_not_exist = {
            'access_type': 'ip',
            'access_to': '100.112.0.99',
            'access_level': 'rw',
        }
        result = self.driver.deny_access(self._context, self.share_nfs,
                                         access_ip_not_exist,
                                         self.share_server)
        self.assertIsNone(result)

    def test_deny_access_cifs_fail(self):
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
                                self.access_ip_exist, self.share_server)
        self.assertTrue(self.driver.plugin.helper.deny_flag)

    def test_deny_access_user_success(self):
        self.driver.plugin.helper.login()
        self.deny_flag = False
        self.driver.deny_access(self._context, self.share_cifs,
                                self.access_user_exist, self.share_server)
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
        self.recreate_fake_conf_file(logical_port="")
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

    @dec_driver_handles_share_servers
    def test_setup_server_success(self):
        backend_details = self.driver.setup_server(self.fake_network_info)
        fake_share_server = {
            'backend_details': backend_details
        }
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        location = self.driver.create_share(self._context, self.share_nfs,
                                            fake_share_server)
        self.assertTrue(db.share_type_get.called)
        self.assertEqual((self.fake_network_allocations[0]['ip_address']
                         + ":/share_fake_uuid"), location)

    @dec_driver_handles_share_servers
    def test_setup_server_with_bond_port_success(self):
        self.recreate_fake_conf_file(logical_port='fake_bond')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        backend_details = self.driver.setup_server(self.fake_network_info)
        fake_share_server = {
            'backend_details': backend_details
        }
        share_type = self.fake_type_not_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        location = self.driver.create_share(self._context, self.share_nfs,
                                            fake_share_server)
        self.assertTrue(db.share_type_get.called)
        self.assertEqual((self.fake_network_allocations[0]['ip_address']
                         + ":/share_fake_uuid"), location)

    @dec_driver_handles_share_servers
    def test_setup_server_logical_port_exist(self):
        def call_logical_port_exist(*args, **kwargs):
            url = args[0]
            method = args[2]
            if url == "/LIF" and method == "GET":
                data = """{"error":{"code":0},"data":[{
                    "ID":"4",
                    "HOMEPORTID":"4",
                    "IPV4ADDR":"111.111.111.109",
                    "IPV4MASK":"255.255.255.0",
                    "OPERATIONALSTATUS":"false"}]}"""
            elif url == "/LIF/4" and method == "PUT":
                data = """{"error":{"code":0}}"""
            else:
                return self.driver.plugin.helper.do_call(*args, **kwargs)

            res_json = jsonutils.loads(data)
            return res_json

        self.mock_object(self.driver.plugin.helper, "create_logical_port")
        with mock.patch.object(self.driver.plugin.helper,
                               'call') as mock_call:
            mock_call.side_effect = call_logical_port_exist
            backend_details = self.driver.setup_server(self.fake_network_info)
            self.assertEqual(backend_details['ip'],
                             self.fake_network_allocations[0]['ip_address'])
            self.assertEqual(
                0, self.driver.plugin.helper.create_logical_port.call_count)

    @dec_driver_handles_share_servers
    def test_setup_server_vlan_exist(self):
        def call_vlan_exist(*args, **kwargs):
            url = args[0]
            method = args[2]
            if url == "/vlan" and method == "GET":
                data = """{"error":{"code":0},"data":[{
                    "ID":"4",
                    "NAME":"fake_vlan",
                    "PORTID":"4",
                    "TAG":"2"}]}"""
            else:
                return self.driver.plugin.helper.do_call(*args, **kwargs)

            res_json = jsonutils.loads(data)
            return res_json

        self.mock_object(self.driver.plugin.helper, "create_vlan")
        with mock.patch.object(self.driver.plugin.helper,
                               'call') as mock_call:
            mock_call.side_effect = call_vlan_exist
            backend_details = self.driver.setup_server(self.fake_network_info)
            self.assertEqual(backend_details['ip'],
                             self.fake_network_allocations[0]['ip_address'])
            self.assertEqual(
                0, self.driver.plugin.helper.create_vlan.call_count)

    def test_setup_server_invalid_ipv4(self):
        netwot_info_invali_ipv4 = self.fake_network_info
        netwot_info_invali_ipv4['network_allocations'][0]['ip_address'] =\
            "::1/128"
        self.assertRaises(exception.InvalidInput,
                          self.driver._setup_server,
                          netwot_info_invali_ipv4)

    @dec_driver_handles_share_servers
    def test_setup_server_network_type_error(self):
        vxlan_netwotk_info = self.fake_network_info
        vxlan_netwotk_info['network_type'] = 'vxlan'
        self.assertRaises(exception.NetworkBadConfigurationException,
                          self.driver.setup_server,
                          vxlan_netwotk_info)

    @dec_driver_handles_share_servers
    def test_setup_server_port_conf_miss(self):
        self.recreate_fake_conf_file(logical_port='')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        backend_details = self.driver.setup_server(self.fake_network_info)
        self.assertEqual(self.fake_network_allocations[0]['ip_address'],
                         backend_details['ip'])

    @dec_driver_handles_share_servers
    def test_setup_server_port_offline_error(self):
        self.mock_object(self.driver.plugin,
                         '_get_online_port',
                         mock.Mock(return_value=(None, None)))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          self.fake_network_info)
        self.assertTrue(self.driver.plugin._get_online_port.called)

    @dec_driver_handles_share_servers
    def test_setup_server_port_not_exist(self):
        self.mock_object(self.driver.plugin.helper,
                         'get_port_id',
                         mock.Mock(return_value=None))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          self.fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_port_id.called)

    @dec_driver_handles_share_servers
    def test_setup_server_port_type_not_exist(self):
        self.mock_object(self.driver.plugin,
                         '_get_optimal_port',
                         mock.Mock(return_value=('CTE0.A.H2', '8')))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          self.fake_network_info)
        self.assertTrue(self.driver.plugin._get_optimal_port.called)

    @dec_driver_handles_share_servers
    def test_setup_server_choose_eth_port(self):
        self.recreate_fake_conf_file(logical_port='CTE0.A.H0;fake_bond')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)

        self.mock_object(self.driver.plugin.helper,
                         'get_all_vlan',
                         mock.Mock(return_value=[{'NAME': 'fake_bond.10'}]))
        fake_network_info = self.fake_network_info
        backend_details = self.driver.setup_server(fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_all_vlan.called)
        self.assertEqual(self.fake_network_allocations[0]['ip_address'],
                         backend_details['ip'])

    @dec_driver_handles_share_servers
    def test_setup_server_choose_bond_port(self):
        self.recreate_fake_conf_file(logical_port='CTE0.A.H0;fake_bond')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)

        self.mock_object(self.driver.plugin.helper,
                         'get_all_vlan',
                         mock.Mock(return_value=[{'NAME': 'CTE0.A.H0.10'}]))
        fake_network_info = self.fake_network_info
        backend_details = self.driver.setup_server(fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_all_vlan.called)
        self.assertEqual(self.fake_network_allocations[0]['ip_address'],
                         backend_details['ip'])

    @dec_driver_handles_share_servers
    def test_setup_server_choose_least_logic_port(self):
        self.recreate_fake_conf_file(
            logical_port='CTE0.A.H0;CTE0.A.H2;CTE0.B.H0;BOND0')
        self.driver.plugin.configuration.manila_huawei_conf_file = (
            self.fake_conf_file)
        fake_network_info = {
            'server_id': '0',
            'segmentation_id': None,
            'cidr': '111.111.111.0/24',
            'network_allocations': self.fake_network_allocations,
            'network_type': None,
        }
        self.mock_object(self.driver.plugin, '_get_online_port',
                         mock.Mock(return_value=(['CTE0.A.H0', 'CTE0.A.H2',
                                                  'CTE0.B.H0'], ['BOND0'])))
        self.mock_object(self.driver.plugin.helper, 'get_all_logical_port',
                         mock.Mock(return_value=[
                             {'HOMEPORTTYPE': constants.PORT_TYPE_ETH,
                              'HOMEPORTNAME': 'CTE0.A.H0'},
                             {'HOMEPORTTYPE': constants.PORT_TYPE_VLAN,
                              'HOMEPORTNAME': 'CTE0.B.H0.10'},
                             {'HOMEPORTTYPE': constants.PORT_TYPE_BOND,
                              'HOMEPORTNAME': 'BOND0'}]))
        self.mock_object(self.driver.plugin.helper,
                         'get_port_id',
                         mock.Mock(return_value=4))

        backend_details = self.driver.setup_server(fake_network_info)

        self.assertEqual(self.fake_network_allocations[0]['ip_address'],
                         backend_details['ip'])
        self.driver.plugin._get_online_port.assert_called_once_with(
            ['CTE0.A.H0', 'CTE0.A.H2',  'CTE0.B.H0', 'BOND0'])
        self.assertTrue(self.driver.plugin.helper.get_all_logical_port.called)
        self.driver.plugin.helper.get_port_id.assert_called_once_with(
            'CTE0.A.H2', constants.PORT_TYPE_ETH)

    @dec_driver_handles_share_servers
    def test_setup_server_create_vlan_fail(self):
        def call_create_vlan_fail(*args, **kwargs):
            url = args[0]
            method = args[2]
            if url == "/vlan" and method == "POST":
                data = """{"error":{"code":1}}"""
                res_json = jsonutils.loads(data)
                return res_json
            else:
                return self.driver.plugin.helper.do_call(*args, **kwargs)

        with mock.patch.object(self.driver.plugin.helper,
                               'call') as mock_call:
            mock_call.side_effect = call_create_vlan_fail
            self.assertRaises(exception.InvalidShare,
                              self.driver.setup_server,
                              self.fake_network_info)

    @dec_driver_handles_share_servers
    def test_setup_server_create_logical_port_fail(self):
        def call_create_logical_port_fail(*args, **kwargs):
            url = args[0]
            method = args[2]
            if url == "/LIF" and method == "POST":
                data = """{"error":{"code":1}}"""
                res_json = jsonutils.loads(data)
                return res_json
            else:
                return self.driver.plugin.helper.do_call(*args, **kwargs)

        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [
            self.fake_active_directory, self.fake_ldap]
        self.mock_object(self.driver.plugin.helper, "delete_vlan")
        self.mock_object(self.driver.plugin.helper, "delete_AD_config")
        self.mock_object(self.driver.plugin.helper, "delete_LDAP_config")
        self.mock_object(self.driver.plugin.helper,
                         "get_AD_config",
                         mock.Mock(side_effect=[None,
                                                {'DOMAINSTATUS': '1'},
                                                {'DOMAINSTATUS': '0'}]))
        self.mock_object(
            self.driver.plugin.helper,
            "get_LDAP_config",
            mock.Mock(
                side_effect=[None, {'BASEDN': 'dc=huawei,dc=com'}]))
        with mock.patch.object(self.driver.plugin.helper,
                               'call') as mock_call:
            mock_call.side_effect = call_create_logical_port_fail
            self.assertRaises(exception.InvalidShare,
                              self.driver.setup_server,
                              fake_network_info)
            self.assertTrue(self.driver.plugin.helper.get_AD_config.called)
            self.assertTrue(self.driver.plugin.helper.get_LDAP_config.called)
            self.assertEqual(
                1, self.driver.plugin.helper.delete_vlan.call_count)
            self.assertEqual(
                1, self.driver.plugin.helper.delete_AD_config.call_count)
            self.assertEqual(
                1, self.driver.plugin.helper.delete_LDAP_config.call_count)

    @dec_driver_handles_share_servers
    def test_setup_server_with_ad_domain_success(self):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_active_directory]
        self.mock_object(self.driver.plugin.helper,
                         "get_AD_config",
                         mock.Mock(
                             side_effect=[None,
                                          {'DOMAINSTATUS': '0',
                                           'FULLDOMAINNAME': 'huawei.com'},
                                          {'DOMAINSTATUS': '1',
                                           'FULLDOMAINNAME': 'huawei.com'}]))
        backend_details = self.driver.setup_server(fake_network_info)
        self.assertEqual(self.fake_network_allocations[0]['ip_address'],
                         backend_details['ip'])
        self.assertTrue(self.driver.plugin.helper.get_AD_config.called)

    @ddt.data(
        "100.97.5.87",
        "100.97.5.87,100.97.5.88",
        "100.97.5.87,100.97.5.88,100.97.5.89"
    )
    @dec_driver_handles_share_servers
    def test_setup_server_with_ldap_domain_success(self, server_ips):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_ldap]
        fake_network_info['security_services'][0]['server'] = server_ips
        self.mock_object(
            self.driver.plugin.helper,
            "get_LDAP_config",
            mock.Mock(
                side_effect=[None, {'BASEDN': 'dc=huawei,dc=com'}]))
        backend_details = self.driver.setup_server(fake_network_info)
        self.assertEqual(self.fake_network_allocations[0]['ip_address'],
                         backend_details['ip'])
        self.assertTrue(self.driver.plugin.helper.get_LDAP_config.called)

    @dec_driver_handles_share_servers
    def test_setup_server_with_ldap_domain_fail(self):
        server_ips = "100.97.5.87,100.97.5.88,100.97.5.89,100.97.5.86"
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_ldap]
        fake_network_info['security_services'][0]['server'] = server_ips
        self.mock_object(
            self.driver.plugin.helper,
            "get_LDAP_config",
            mock.Mock(
                side_effect=[None, {'BASEDN': 'dc=huawei,dc=com'}]))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_LDAP_config.called)

    @ddt.data(
        {'type': 'fake_unsupport'},
        {'type': 'active_directory',
         'dns_ip': '',
         'user': '',
         'password': '',
         'domain': ''},
        {'type': 'ldap',
         'server': '',
         'domain': ''},
    )
    @dec_driver_handles_share_servers
    def test_setup_server_with_security_service_invalid(self, data):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [data]
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)

    @dec_driver_handles_share_servers
    def test_setup_server_with_security_service_number_invalid(self):
        fake_network_info = self.fake_network_info
        ss = [
            {'type': 'fake_unsupport'},
            {'type': 'active_directory',
             'dns_ip': '',
             'user': '',
             'password': '',
             'domain': ''},
            {'type': 'ldap',
             'server': '',
             'domain': ''},
        ]
        fake_network_info['security_services'] = ss
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)

    @dec_driver_handles_share_servers
    def test_setup_server_dns_exist_error(self):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_active_directory]
        self.mock_object(self.driver.plugin.helper,
                         "get_DNS_ip_address",
                         mock.Mock(return_value=['100.97.5.85']))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_DNS_ip_address.called)

    @dec_driver_handles_share_servers
    def test_setup_server_ad_exist_error(self):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_active_directory]
        self.mock_object(self.driver.plugin.helper,
                         "get_AD_config",
                         mock.Mock(
                             return_value={'DOMAINSTATUS': '1',
                                           'FULLDOMAINNAME': 'huawei.com'}))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_AD_config.called)

    @dec_driver_handles_share_servers
    def test_setup_server_ldap_exist_error(self):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_ldap]
        self.mock_object(self.driver.plugin.helper,
                         "get_LDAP_config",
                         mock.Mock(
                             return_value={'LDAPSERVER': '100.97.5.87'}))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_LDAP_config.called)

    @dec_driver_handles_share_servers
    def test_setup_server_with_dns_fail(self):
        fake_network_info = self.fake_network_info
        fake_active_directory = self.fake_active_directory
        ip_list = "100.97.5.5,100.97.5.6,100.97.5.7,100.97.5.8"
        fake_active_directory['dns_ip'] = ip_list
        fake_network_info['security_services'] = [fake_active_directory]
        self.mock_object(
            self.driver.plugin.helper,
            "get_AD_config",
            mock.Mock(side_effect=[None, {'DOMAINSTATUS': '1'}]))
        self.assertRaises(exception.InvalidInput,
                          self.driver.setup_server,
                          fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_AD_config.called)

    @dec_driver_handles_share_servers
    def test_setup_server_with_ad_domain_fail(self):
        fake_network_info = self.fake_network_info
        fake_network_info['security_services'] = [self.fake_active_directory]
        self.mock_object(self.driver.plugin,
                         '_get_wait_interval',
                         mock.Mock(return_value=1))
        self.mock_object(self.driver.plugin,
                         '_get_timeout',
                         mock.Mock(return_value=1))
        self.mock_object(
            self.driver.plugin.helper,
            "get_AD_config",
            mock.Mock(side_effect=[None,
                                   {'DOMAINSTATUS': '0',
                                    'FULLDOMAINNAME': 'huawei.com'}]))
        self.mock_object(self.driver.plugin.helper, "set_DNS_ip_address")
        self.assertRaises(exception.InvalidShare,
                          self.driver.setup_server,
                          fake_network_info)
        self.assertTrue(self.driver.plugin.helper.get_AD_config.called)
        self.assertTrue(self.driver.plugin._get_wait_interval.called)
        self.assertTrue(self.driver.plugin._get_timeout.called)
        self.assertEqual(
            2, self.driver.plugin.helper.set_DNS_ip_address.call_count)

    def test_teardown_server_success(self):
        server_details = {
            "logical_port_id": "1",
            "vlan_id": "2",
            "ad_created": "1",
            "ldap_created": "1",
        }
        security_services = [
            self.fake_ldap,
            self.fake_active_directory
        ]
        self.logical_port_deleted = False
        self.vlan_deleted = False
        self.ad_deleted = False
        self.ldap_deleted = False
        self.dns_deleted = False

        def fake_teardown_call(*args, **kwargs):
            url = args[0]
            method = args[2]
            if url.startswith("/LIF"):
                if method == "GET":
                    data = """{"error":{"code":0},"data":[{
                            "ID":"1"}]}"""
                elif method == "DELETE":
                    data = """{"error":{"code":0}}"""
                    self.logical_port_deleted = True
            elif url.startswith("/vlan"):
                if method == "GET":
                    data = """{"error":{"code":0},"data":[{
                            "ID":"2"}]}"""
                elif method == "DELETE":
                    data = """{"error":{"code":1073813505}}"""
                    self.vlan_deleted = True
            elif url == "/AD_CONFIG":
                if method == "PUT":
                    data = """{"error":{"code":0}}"""
                    self.ad_deleted = True
                elif method == "GET":
                    if self.ad_deleted:
                        data = """{"error":{"code":0},"data":{
                            "DOMAINSTATUS":"0"}}"""
                    else:
                        data = """{"error":{"code":0},"data":{
                            "DOMAINSTATUS":"1",
                            "FULLDOMAINNAME":"huawei.com"}}"""
                else:
                    data = """{"error":{"code":0}}"""
            elif url == "/LDAP_CONFIG":
                if method == "DELETE":
                    data = """{"error":{"code":0}}"""
                    self.ldap_deleted = True
                elif method == "GET":
                    if self.ldap_deleted:
                        data = """{"error":{"code":0}}"""
                    else:
                        data = """{"error":{"code":0},"data":{
                            "LDAPSERVER":"100.97.5.87",
                            "BASEDN":"dc=huawei,dc=com"}}"""
                else:
                    data = """{"error":{"code":0}}"""
            elif url == "/DNS_Server":
                if method == "GET":
                    data = "{\"error\":{\"code\":0},\"data\":{\
                        \"ADDRESS\":\"[\\\"100.97.5.5\\\",\\\"\\\"]\"}}"
                elif method == "PUT":
                    data = """{"error":{"code":0}}"""
                    self.dns_deleted = True
                else:
                    data = """{"error":{"code":0}}"""
            else:
                return self.driver.plugin.helper.do_call(*args, **kwargs)

            res_json = jsonutils.loads(data)
            return res_json

        with mock.patch.object(self.driver.plugin.helper,
                               'call') as mock_call:
            mock_call.side_effect = fake_teardown_call
            self.driver._teardown_server(server_details, security_services)
            self.assertTrue(self.logical_port_deleted)
            self.assertTrue(self.vlan_deleted)
            self.assertTrue(self.ad_deleted)
            self.assertTrue(self.ldap_deleted)
            self.assertTrue(self.dns_deleted)

    def test_teardown_server_with_already_deleted(self):
        server_details = {
            "logical_port_id": "1",
            "vlan_id": "2",
            "ad_created": "1",
            "ldap_created": "1",
        }
        security_services = [
            self.fake_ldap,
            self.fake_active_directory
        ]

        self.mock_object(self.driver.plugin.helper,
                         "check_logical_port_exists_by_id",
                         mock.Mock(return_value=False))
        self.mock_object(self.driver.plugin.helper,
                         "check_vlan_exists_by_id",
                         mock.Mock(return_value=False))
        self.mock_object(self.driver.plugin.helper,
                         "get_DNS_ip_address",
                         mock.Mock(return_value=None))
        self.mock_object(self.driver.plugin.helper,
                         "get_AD_domain_name",
                         mock.Mock(return_value=(False, None)))
        self.mock_object(self.driver.plugin.helper,
                         "get_LDAP_domain_server",
                         mock.Mock(return_value=(False, None)))

        self.driver._teardown_server(server_details, security_services)
        self.assertEqual(1, (self.driver.plugin.helper.
                         check_logical_port_exists_by_id.call_count))
        self.assertEqual(1, (self.driver.plugin.helper.
                         check_vlan_exists_by_id.call_count))
        self.assertEqual(1, (self.driver.plugin.helper.
                         get_DNS_ip_address.call_count))
        self.assertEqual(1, (self.driver.plugin.helper.
                         get_AD_domain_name.call_count))
        self.assertEqual(1, (self.driver.plugin.helper.
                         get_LDAP_domain_server.call_count))

    def test_teardown_server_with_vlan_logical_port_deleted(self):
        server_details = {
            "logical_port_id": "1",
            "vlan_id": "2",
        }

        self.mock_object(self.driver.plugin.helper,
                         'get_all_logical_port',
                         mock.Mock(return_value=[{'ID': '4'}]))
        self.mock_object(self.driver.plugin.helper,
                         'get_all_vlan',
                         mock.Mock(return_value=[{'ID': '4'}]))
        self.driver._teardown_server(server_details, None)
        self.assertEqual(1, (self.driver.plugin.helper.
                         get_all_logical_port.call_count))
        self.assertEqual(1, (self.driver.plugin.helper.
                         get_all_vlan.call_count))

    def test_teardown_server_with_empty_detail(self):
        server_details = {}
        with mock.patch.object(connection.LOG, 'debug') as mock_debug:
            self.driver._teardown_server(server_details, None)
            mock_debug.assert_called_with('Server details are empty.')

    @ddt.data({"share_proto": "NFS",
               "path": ["100.115.10.68:/share_fake_uuid"]},
              {"share_proto": "CIFS",
               "path": ["\\\\100.115.10.68\\share_fake_uuid"]})
    @ddt.unpack
    def test_ensure_share_sucess(self, share_proto, path):
        share = self._get_share_by_proto(share_proto)

        self.driver.plugin.helper.login()
        location = self.driver.ensure_share(self._context,
                                            share,
                                            self.share_server)
        self.assertEqual(path, location)

    @ddt.data({"share_proto": "NFS",
               "path": ["111.111.111.109:/share_fake_uuid"]},
              {"share_proto": "CIFS",
               "path": ["\\\\111.111.111.109\\share_fake_uuid"]})
    @ddt.unpack
    @dec_driver_handles_share_servers
    def test_ensure_share_with_share_server_sucess(self, share_proto, path):
        share = self._get_share_by_proto(share_proto)
        backend_details = self.driver.setup_server(self.fake_network_info)
        fake_share_server = {'backend_details': backend_details}

        self.driver.plugin.helper.login()
        location = self.driver.ensure_share(self._context,
                                            share,
                                            fake_share_server)
        self.assertEqual(path, location)

    @ddt.data({"share_proto": "NFS"},
              {"share_proto": "CIFS"})
    @ddt.unpack
    def test_ensure_share_get_share_fail(self, share_proto):
        share = self._get_share_by_proto(share_proto)
        self.mock_object(self.driver.plugin.helper,
                         '_get_share_by_name',
                         mock.Mock(return_value={}))

        self.driver.plugin.helper.login()
        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.ensure_share,
                          self._context,
                          share,
                          self.share_server)

    def test_ensure_share_get_filesystem_status_fail(self):
        self.driver.plugin.helper.fs_status_flag = False
        share = self.share_nfs_thickfs

        self.driver.plugin.helper.login()
        self.assertRaises(exception.StorageResourceException,
                          self.driver.ensure_share,
                          self._context,
                          share,
                          self.share_server)

    def create_fake_conf_file(self, fake_conf_file,
                              product_flag=True, username_flag=True,
                              pool_node_flag=True, timeout_flag=True,
                              wait_interval_flag=True,
                              alloctype_value='Thick',
                              multi_url=False,
                              logical_port='100.115.10.68'):
        doc = xml.dom.minidom.Document()
        config = doc.createElement('Config')
        doc.appendChild(config)

        storage = doc.createElement('Storage')
        config.appendChild(storage)

        if self.configuration.driver_handles_share_servers:
            port0 = doc.createElement('Port')
            port0_text = doc.createTextNode(logical_port)
            port0.appendChild(port0_text)
            storage.appendChild(port0)
        else:
            controllerip0 = doc.createElement('LogicalPortIP')
            controllerip0_text = doc.createTextNode(logical_port)
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

        storagepool = doc.createElement('StoragePool')
        if pool_node_flag:
            pool_text = doc.createTextNode('OpenStack_Pool;OpenStack_Pool2; ;')
        else:
            pool_text = doc.createTextNode('')
        storagepool.appendChild(pool_text)

        timeout = doc.createElement('Timeout')

        if timeout_flag:
            timeout_text = doc.createTextNode('60')
        else:
            timeout_text = doc.createTextNode('')
        timeout.appendChild(timeout_text)

        waitinterval = doc.createElement('WaitInterval')
        if wait_interval_flag:
            waitinterval_text = doc.createTextNode('3')
        else:
            waitinterval_text = doc.createTextNode('')
        waitinterval.appendChild(waitinterval_text)

        NFSClient = doc.createElement('NFSClient')

        virtualip = doc.createElement('IP')
        virtualip_text = doc.createTextNode('100.112.0.1')
        virtualip.appendChild(virtualip_text)
        NFSClient.appendChild(virtualip)
        CIFSClient = doc.createElement('CIFSClient')

        username = doc.createElement('UserName')
        username_text = doc.createTextNode('user_name')
        username.appendChild(username_text)
        CIFSClient.appendChild(username)

        userpassword = doc.createElement('UserPassword')
        userpassword_text = doc.createTextNode('user_password')
        userpassword.appendChild(userpassword_text)
        CIFSClient.appendChild(userpassword)

        lun.appendChild(NFSClient)
        lun.appendChild(CIFSClient)
        lun.appendChild(timeout)
        lun.appendChild(waitinterval)
        lun.appendChild(storagepool)

        if alloctype_value:
            alloctype = doc.createElement('AllocType')
            alloctype_text = doc.createTextNode(alloctype_value)
            alloctype.appendChild(alloctype_text)
            lun.appendChild(alloctype)

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
                                alloctype_value='Thick',
                                multi_url=False,
                                logical_port='100.115.10.68'):
        self.tmp_dir = tempfile.mkdtemp()
        self.fake_conf_file = self.tmp_dir + '/manila_huawei_conf.xml'
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.create_fake_conf_file(self.fake_conf_file, product_flag,
                                   username_flag, pool_node_flag,
                                   timeout_flag, wait_interval_flag,
                                   alloctype_value, multi_url,
                                   logical_port)
        self.addCleanup(os.remove, self.fake_conf_file)
