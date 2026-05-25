# Copyright 2026 Weka.IO Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Fake objects and API responses used in Weka driver unit tests."""

from oslo_utils import uuidutils


def _uid():
    return uuidutils.generate_uuid()


FAKE_FS_UID = 'fs-uid-1234'
# Must match _share_name('share-uuid-1234'): prefix 'manila_' + hex-stripped ID
FAKE_FS_NAME = 'manila_shareuuid1234'
FAKE_GROUP_UID = 'grp-uid-5678'
FAKE_GROUP_NAME = 'default'
FAKE_SNAP_UID = 'snap-uid-abcd'
# Must match _snapshot_name('snapshot-uuid-0001'):
# prefix 's_' + hex-stripped ID
FAKE_SNAP_NAME = 's_snapshotuuid0001'
FAKE_ORG_UID = 'org-uid-9999'
FAKE_PERM_UID = 'perm-uid-aaaa'
FAKE_CG_UID = 'cg-uid-bbbb'


def fake_filesystem(uid=FAKE_FS_UID, name=FAKE_FS_NAME,
                    group_name=FAKE_GROUP_NAME,
                    total_capacity=10 * 1024 ** 3,
                    used_size_bytes=1 * 1024 ** 3,
                    auth_required=False, encrypted=False):
    return {
        'uid': uid,
        'name': name,
        'groupName': group_name,
        'totalCapacity': total_capacity,
        'usedSizeBytes': used_size_bytes,
        'availableTotal': total_capacity - used_size_bytes,
        'authRequired': auth_required,
        'encrypted': encrypted,
        'status': 'READY',
    }


def fake_filesystem_group(uid=FAKE_GROUP_UID, name=FAKE_GROUP_NAME):
    return {
        'uid': uid,
        'name': name,
        'targetSsdRetention': 86400,
        'startDemote': 10,
    }


def fake_snapshot(uid=FAKE_SNAP_UID, name=FAKE_SNAP_NAME,
                  fs_uid=FAKE_FS_UID, is_writable=False):
    return {
        'uid': uid,
        'name': name,
        'filesystemUid': fs_uid,
        'isWritable': is_writable,
        'creationTime': '2024-01-01T00:00:00Z',
        'accessPoint': '@GMT-2024.01.01-00.00.00',
    }


def fake_new_filesystem():
    """Destination filesystem for create_share_from_snapshot tests."""
    return fake_filesystem(uid=FAKE_NEW_FS_UID, name=FAKE_NEW_FS_NAME)


def fake_organization(uid=FAKE_ORG_UID, name='TestOrg', org_id=1,
                      ssd_quota=0, total_quota=0,
                      enforce_fs_auth=False):
    # Matches the live Weka v2 shape (snake_case, includes 'id').
    return {
        'uid': uid,
        'id': org_id,
        'name': name,
        'ssd_quota': ssd_quota,
        'total_quota': total_quota,
        'enforce_fs_auth': enforce_fs_auth,
    }


def fake_user(username='manila', role='TenantAdmin', org_name='TestOrg',
              org_id=1, uid=None):
    return {
        'uid': uid or _uid(),
        'username': username,
        'role': role,
        'org_name': org_name,
        'org_id': org_id,
        'source': 'Internal',
    }


def fake_nfs_permission(uid=FAKE_PERM_UID, fs_name=FAKE_FS_NAME,
                        cg_uid=FAKE_CG_UID,
                        cg_name='manila-abcd1234-efgh5678',
                        path='/', access_type='RW',
                        permission_type=None):
    return {
        'uid': uid,
        'filesystem': fs_name,    # Weka v5: filesystem name (not UID)
        'group': cg_name,         # Weka v5: client group name
        'clientGroupId': cg_uid,
        'path': path,
        'accessType': access_type,
        # permission_type is what the driver checks for access-level updates.
        'permission_type': (permission_type
                            if permission_type is not None
                            else access_type),
    }


def fake_client_group(uid=FAKE_CG_UID, name='manila-abcd1234-efgh5678'):
    return {'uid': uid, 'name': name}


FAKE_POLICY_UID = 'pol-uid-eeee'


def fake_security_policy(uid=FAKE_POLICY_UID, name='manila-shareuui-rw',
                         ips=None, action='Allow', read_only=False):
    """A security policy as read back from the API, keyed on ``ips``."""
    return {
        'uid': uid,
        'name': name,
        'action': action,
        'ips': list(ips or []),
        'read_only': read_only,
    }


def fake_client_group_ip_rule(ip):
    """One IP rule as the cluster reports it inside a client group.

    NOTE the key is ``rule``, not ``ip``, and the value is always stored
    as ``address/dotted-mask`` -- a bare address comes back as
    ``203.0.113.253/255.255.255.255``.  Fixtures that used ``{'ip': ...}``
    matched the driver's own wrong assumption, so its de-dup check could
    never fire and every re-apply issued a duplicate add.
    """
    return {
        'id': 'NfsClientGroupRuleId<0>',
        'uid': 'rule-uid-0000',
        'type': 'IP',
        'rule': ip if '/' in ip else '{}/255.255.255.255'.format(ip),
    }


def fake_client_group_detail(uid=FAKE_CG_UID,
                             name='manila-abcd1234-efgh5678',
                             rules=None):
    """Detailed client group as returned by get_client_group()."""
    return {'uid': uid, 'name': name, 'rules': rules or []}


def fake_capacity(total_bytes=100 * 1024 ** 3, used_bytes=30 * 1024 ** 3):
    return {
        'totalBytes': total_bytes,
        'usedBytes': used_bytes,
    }


def fake_cluster_status(name='test-cluster', version='4.2.0'):
    return {'name': name, 'release': version, 'status': 'OK'}


def fake_mount_token(token='fake-mount-token-xyz'):
    return {'token': token}


def fake_quota(inode_id=12345, hard_limit=10 * 1024 ** 3,
               soft_limit=None, used_bytes=1 * 1024 ** 3):
    return {
        'inodeId': inode_id,
        'hardLimitBytes': hard_limit,
        'softLimitBytes': soft_limit,
        'usedBytes': used_bytes,
    }


FAKE_SHARE_ID = 'share-uuid-1234'
FAKE_SNAPSHOT_ID = 'snapshot-uuid-0001'
FAKE_PROJECT_ID = 'proj-uuid-5678'

# The new share created from a snapshot, distinct from its parent.
FAKE_NEW_SHARE_ID = 'new-share-uuid-9999'
FAKE_NEW_FS_UID = 'new-fs-uid-9999'
FAKE_NEW_FS_NAME = 'manila_newshareuuid9999'
FAKE_CG_RULE_UID = 'rule-uid-cccc'


def fake_share(share_id=FAKE_SHARE_ID, size=10, proto='WEKAFS',
               export_locations=None, project_id=FAKE_PROJECT_ID,
               share_type_id=None):
    if export_locations is None:
        export_locations = [{
            'path': 'weka-host/{}'.format('manila_' + share_id),
            'is_admin_only': False,
            'metadata': {
                'weka_fs_uid': FAKE_FS_UID,
                'weka_fs_name': 'manila_' + share_id,
            },
        }]
    return {
        'id': share_id,
        'size': size,
        'share_proto': proto,
        'export_locations': export_locations,
        'display_name': 'test-share',
        'project_id': project_id,
        'share_type_id': share_type_id,
    }


def fake_snapshot_model(snapshot_id=FAKE_SNAPSHOT_ID,
                        share_id=FAKE_SHARE_ID):
    return {
        'id': snapshot_id,
        'share_instance_id': share_id,
        'name': 'snap_{}'.format(snapshot_id),
        'share': fake_share(share_id=share_id),
    }


def fake_access_rule(rule_id=None, access_type='ip',
                     access_to='192.0.2.0/24',
                     access_level='rw'):
    return {
        'access_id': rule_id or _uid(),
        'id': rule_id or _uid(),
        'access_type': access_type,
        'access_to': access_to,
        'access_level': access_level,
    }
