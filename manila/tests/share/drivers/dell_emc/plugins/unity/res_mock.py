# Copyright (c) 2016 EMC Corporation.
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

import mock
from oslo_log import log

from manila.share import configuration as conf
from manila.share.drivers.dell_emc.plugins.unity import client
from manila.share.drivers.dell_emc.plugins.unity import connection
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_share
from manila.tests.share.drivers.dell_emc.plugins.unity import fake_exceptions
from manila.tests.share.drivers.dell_emc.plugins.unity import utils

client.storops_ex = fake_exceptions
connection.storops_ex = fake_exceptions

LOG = log.getLogger(__name__)

SYMBOL_TYPE = '_type'
SYMBOL_PROPERTIES = '_properties'
SYMBOL_METHODS = '_methods'
SYMBOL_SIDE_EFFECT = '_side_effect'
SYMBOL_RAISE = '_raise'


def _has_side_effect(node):
    return isinstance(node, dict) and SYMBOL_SIDE_EFFECT in node


def _has_raise(node):
    return isinstance(node, dict) and SYMBOL_RAISE in node


def fake_share_server(**kwargs):
    share_server = {
        'instance_id': 'fake_instance_id',
        'backend_details': {},
    }

    share_server.update(kwargs)

    return db_fakes.FakeModel(share_server)


def fake_network_info(**kwargs):
    network_info = {
        'id': 'fake_net_id',
        'name': 'net_name',
        'subnet': [],
    }
    network_info.update(kwargs)
    return network_info


def fake_server_detail(**kwargs):
    server_detail = {
        'share_server_name': 'fake_server_name',
    }
    server_detail.update(kwargs)
    return server_detail


def fake_security_services(**kwargs):
    return kwargs['services']


def fake_access(**kwargs):
    access = {}
    access.update(kwargs)
    return access


class FakeEMCShareDriver(object):
    def __init__(self):
        self.configuration = conf.Configuration(None)
        self.configuration.emc_share_backend = 'unity'
        self.configuration.emc_nas_server = '192.168.1.1'
        self.configuration.emc_nas_login = 'fake_user'
        self.configuration.emc_nas_password = 'fake_password'
        self.configuration.share_backend_name = 'EMC_NAS_Storage'
        self.configuration.vnx_server_meta_pool = 'nas_server_pool'
        self.configuration.unity_server_meta_pool = 'nas_server_pool'
        self.configuration.local_conf.max_over_subscription_ratio = 20


STATS = dict(
    share_backend_name='Unity',
    vendor_name='EMC',
    storage_protocol='NFS_CIFS',
    driver_version='2.0.0,',
    pools=[],
)


class DriverResourceMock(dict):
    fake_func_mapping = {}

    def __init__(self, yaml_file):
        yaml_dict = utils.load_yaml(yaml_file)
        if isinstance(yaml_dict, dict):
            for name, body in yaml_dict.items():
                if isinstance(body, dict):
                    props = body[SYMBOL_PROPERTIES]
                    if isinstance(props, dict):
                        for prop_name, prop_value in props.items():
                            if isinstance(prop_value, dict) and prop_value:
                                # get the first key as the convert function
                                func_name = list(prop_value.keys())[0]
                                if func_name.startswith('_'):
                                    func = getattr(self, func_name)
                                    props[prop_name] = (
                                        func(**prop_value[func_name]))
                    if body[SYMBOL_TYPE] in self.fake_func_mapping:
                        self[name] = (
                            self.fake_func_mapping[body[SYMBOL_TYPE]](**props))


class ManilaResourceMock(DriverResourceMock):
    fake_func_mapping = {
        'share': fake_share.fake_share,
        'snapshot': fake_share.fake_snapshot,
        'network_info': fake_network_info,
        'share_server': fake_share_server,
        'server_detail': fake_server_detail,
        'security_services': fake_security_services,
        'access': fake_access,
    }

    def __init__(self, yaml_file):
        super(ManilaResourceMock, self).__init__(yaml_file)


class StorageObjectMock(object):
    PROPS = 'props'

    def __init__(self, yaml_dict):
        self.__dict__[StorageObjectMock.PROPS] = {}
        props = yaml_dict.get(SYMBOL_PROPERTIES, None)
        if props:
            for k, v in props.items():
                setattr(self, k, StoragePropertyMock(k, v)())

        methods = yaml_dict.get(SYMBOL_METHODS, None)
        if methods:
            for k, v in methods.items():
                setattr(self, k, StorageMethodMock(k, v))

    def __setattr__(self, key, value):
        self.__dict__[StorageObjectMock.PROPS][key] = value

    def __getattr__(self, item):
        try:
            super(StorageObjectMock, self).__getattr__(item)
        except AttributeError:
            return self.__dict__[StorageObjectMock.PROPS][item]
        except KeyError:
            raise KeyError('No such method or property for mock object.')


class StoragePropertyMock(mock.PropertyMock):
    def __init__(self, name, property_body):
        return_value = property_body
        side_effect = None

        # only support return_value and side_effect for property
        if _has_side_effect(property_body):
            side_effect = property_body[SYMBOL_SIDE_EFFECT]
            return_value = None

        if side_effect:
            super(StoragePropertyMock, self).__init__(
                name=name,
                side_effect=side_effect)
        elif return_value:
            super(StoragePropertyMock, self).__init__(
                name=name,
                return_value=_build_mock_object(return_value))
        else:
            super(StoragePropertyMock, self).__init__(
                name=name,
                return_value=return_value)


class StorageMethodMock(mock.Mock):
    def __init__(self, name, method_body):
        return_value = method_body
        exception = None
        side_effect = None

        # support return_value, side_effect and exception for method
        if _has_side_effect(method_body) or _has_raise(method_body):
            exception = method_body.get(SYMBOL_RAISE, None)
            side_effect = method_body.get(SYMBOL_SIDE_EFFECT, None)
            return_value = None

        if exception:
            if isinstance(exception, dict) and exception:
                ex_name = list(exception.keys())[0]
                ex = getattr(fake_exceptions, ex_name)
            super(StorageMethodMock, self).__init__(
                name=name,
                side_effect=ex(exception[ex_name]))
        elif side_effect:
            super(StorageMethodMock, self).__init__(
                name=name,
                side_effect=_build_mock_object(side_effect))
        elif return_value is not None:
            super(StorageMethodMock, self).__init__(
                name=name,
                return_value=_build_mock_object(return_value))
        else:
            super(StorageMethodMock, self).__init__(
                name=name, return_value=None)


class StorageResourceMock(dict):
    def __init__(self, yaml_file):
        yaml_dict = utils.load_yaml(yaml_file)
        if isinstance(yaml_dict, dict):
            for section, sec_body in yaml_dict.items():
                self[section] = {}
                if isinstance(sec_body, dict):
                    for obj_name, obj_body in sec_body.items():
                        self[section][obj_name] = _build_mock_object(obj_body)


def _is_mock_object(yaml_info):
    return (isinstance(yaml_info, dict) and
            (SYMBOL_PROPERTIES in yaml_info or SYMBOL_METHODS in yaml_info))


def _build_mock_object(yaml_dict):
    if _is_mock_object(yaml_dict):
        return StorageObjectMock(yaml_dict)
    elif isinstance(yaml_dict, dict):
        return {k: _build_mock_object(v) for k, v in yaml_dict.items()}
    elif isinstance(yaml_dict, list):
        return [_build_mock_object(each) for each in yaml_dict]
    else:
        return yaml_dict


manila_res = ManilaResourceMock('mocked_manila.yaml')
unity_res = StorageResourceMock('mocked_unity.yaml')
STORAGE_RES_MAPPING = {
    'TestClient': unity_res,
    'TestConnection': unity_res,
}


def mock_input(resource):
    def inner_dec(func):
        def decorated(cls, *args, **kwargs):
            if cls._testMethodName in resource:
                storage_res = resource[cls._testMethodName]
                return func(cls, storage_res, *args, **kwargs)

        return decorated

    return inner_dec


mock_client_input = mock_input(unity_res)


def patch_client(func):
    def client_decorator(cls, *args, **kwargs):
        storage_res = {}
        if func.__name__ in STORAGE_RES_MAPPING[cls.__class__.__name__]:
            storage_res = (
                STORAGE_RES_MAPPING[cls.__class__.__name__][func.__name__])
        with utils.patch_system as patched_system:
            if 'unity' in storage_res:
                patched_system.return_value = storage_res['unity']
            _client = client.UnityClient(host='fake_host',
                                         username='fake_user',
                                         password='fake_passwd')
        return func(cls, _client, *args, **kwargs)

    return client_decorator


def mock_driver_input(resource):
    def inner_dec(func):
        def decorated(cls, *args, **kwargs):
            return func(cls, resource, *args, **kwargs)

        return decorated

    return inner_dec


mock_manila_input = mock_driver_input(manila_res)


def patch_connection_init(func):
    def connection_decorator(cls, *args, **kwargs):
        storage_res = {}
        if func.__name__ in STORAGE_RES_MAPPING[cls.__class__.__name__]:
            storage_res = (
                STORAGE_RES_MAPPING[cls.__class__.__name__][func.__name__])
        with utils.patch_system as patched_system:
            if 'unity' in storage_res:
                patched_system.return_value = storage_res['unity']
            conn = connection.UnityStorageConnection(LOG)
            return func(cls, conn, *args, **kwargs)

    return connection_decorator


def do_connection_connect(conn, res):
    conn.config = None
    conn.client = client.UnityClient(host='fake_host',
                                     username='fake_user',
                                     password='fake_passwd')
    conn.pool_conf = ['pool_1', 'pool_2']
    conn.pool_set = set(['pool_1', 'pool_2'])
    conn.reserved_percentage = 0
    conn.max_over_subscription_ratio = 20
    conn.port_set = set(['spa_eth1', 'spa_eth2'])
    conn.nas_server_pool = StorageObjectMock(res['nas_server_pool'])
    conn.storage_processor = StorageObjectMock(res['sp_a'])


def patch_connection(func):
    def connection_decorator(cls, *args, **kwargs):
        storage_res = {}
        if func.__name__ in STORAGE_RES_MAPPING[cls.__class__.__name__]:
            storage_res = (
                STORAGE_RES_MAPPING[cls.__class__.__name__][func.__name__])
        with utils.patch_system as patched_system:
            conn = connection.UnityStorageConnection(LOG)
            if 'unity' in storage_res:
                patched_system.return_value = storage_res['unity']
            do_connection_connect(
                conn, STORAGE_RES_MAPPING[cls.__class__.__name__])
            return func(cls, conn, *args, **kwargs)

    return connection_decorator
