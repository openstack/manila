# Copyright 2013 OpenStack Foundation
# All Rights Reserved
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


from oslo_config import cfg

CONF = cfg.CONF


class FakeServer(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_id')
        self.status = kwargs.pop('status', 'ACTIVE')
        self.networks = kwargs.pop('networks', {'fake_net': 'fake_net_value'})
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, attr):
        return getattr(self, attr)

    def __setitem__(self, attr, value):
        setattr(self, attr, value)

    def get(self, attr, default):
        return getattr(self, attr, default)

    def update(self, *args, **kwargs):
        pass


class FakeKeypair(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_keypair_id')
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeImage(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_image_id')
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeSecurityGroup(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_security_group_id')
        self.name = kwargs.pop('name', 'fake_security_group_name')
        for key, value in kwargs.items():
            setattr(self, key, value)


class API(object):
    """Fake Compute API."""
    def instance_volume_attach(self, ctx, server_id, volume_id, mount_path):
        pass

    def instance_volume_detach(self, ctx, server_id, volume_id):
        pass

    def instance_volumes_list(self, ctx, server_id):
        pass

    def server_create(self, *args, **kwargs):
        pass

    def server_delete(self, *args, **kwargs):
        pass

    def server_get(self, *args, **kwargs):
        pass

    def server_get_by_name_or_id(self, *args, **kwargs):
        pass

    def server_reboot(self, *args, **kwargs):
        pass

    def keypair_list(self, *args, **kwargs):
        pass

    def keypair_import(self, *args, **kwargs):
        pass

    def keypair_delete(self, *args, **kwargs):
        pass

    def image_list(self, *args, **kwargs):
        pass

    def security_group_create(self, *args, **kwargs):
        pass

    def security_group_list(self, *args, **kwargs):
        pass

    def add_security_group_to_server(self, *args, **kwargs):
        pass

    def security_group_rule_create(self, *args, **kwargs):
        pass
