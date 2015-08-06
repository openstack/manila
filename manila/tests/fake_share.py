# Copyright 2013 OpenStack Foundation
# Copyright 2015 Intel, Inc.
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

from manila.tests.db import fakes as db_fakes


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'fake_proto',
        'share_network_id': 'fake share network id',
        'share_server_id': 'fake share server id',
        'export_location': 'fake_location:/fake_share',
        'project_id': 'fake_project_uuid',
        'availability_zone': 'fake_az',
        'snapshot_support': 'True',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_snapshot(**kwargs):
    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_size': 1,
        'share_proto': 'fake_proto',
        'export_location': 'fake_location:/fake_share',
    }
    snapshot.update(kwargs)
    return db_fakes.FakeModel(snapshot)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.1',
        'access_level': 'rw',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)
