# Copyright (c) 2019 Infortrend Technology, Inc.
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


class InfortrendNASTestData(object):

    fake_share_id = ['5a0aa06e-1c57-4996-be46-b81e360e8866',  # NFS
                     'aac4fe64-7a9c-472a-b156-9adbb50b4d29']  # CIFS

    fake_share_name = [fake_share_id[0].replace('-', ''),
                       fake_share_id[1].replace('-', '')]

    fake_channel_ip = ['172.27.112.223', '172.27.113.209']

    fake_service_status_data = ('(64175, 1234, 272, 0)\n\n'
                                '{"cliCode": '
                                '[{"Return": "0x0000", "CLI": "Successful"}], '
                                '"returnCode": [], '
                                '"data": '
                                '[{"A": '
                                '{"NFS": '
                                '{"displayName": "NFS", '
                                '"state_time": "2017-05-04 14:19:53", '
                                '"enabled": true, '
                                '"cpu_rate": "0.0", '
                                '"mem_rate": "0.0", '
                                '"state": "exited", '
                                '"type": "share"}}}]}\n\n')

    fake_folder_status_data = ('(64175, 1234, 1017, 0)\n\n'
                               '{"cliCode": '
                               '[{"Return": "0x0000", "CLI": "Successful"}], '
                               '"returnCode": [], '
                               '"data": '
                               '[{"utility": "1.00", '
                               '"used": "33886208", '
                               '"subshare": true, '
                               '"share": false, '
                               '"worm": "", '
                               '"free": "321931374592", '
                               '"fsType": "xfs", '
                               '"owner": "A", '
                               '"readOnly": false, '
                               '"modifyTime": "2017-04-27 16:16", '
                               '"directory": "/share-pool-01/LV-1", '
                               '"volumeId": "6541BAFB2E6C57B6", '
                               '"mounted": true, '
                               '"size": "321965260800"}, '
                               '{"utility": "1.00", '
                               '"used": "33779712", '
                               '"subshare": false, '
                               '"share": false, '
                               '"worm": "", '
                               '"free": "107287973888", '
                               '"fsType": "xfs", '
                               '"owner": "A", '
                               '"readOnly": false, '
                               '"modifyTime": "2017-04-27 15:45", '
                               '"directory": "/share-pool-02/LV-1", '
                               '"volumeId": "147A8FB67DA39914", '
                               '"mounted": true, '
                               '"size": "107321753600"}]}\n\n')

    fake_nfs_status_off = [{
        'A': {
            'NFS': {
                'displayName': 'NFS',
                'state_time': '2017-05-04 14:19:53',
                'enabled': False,
                'cpu_rate': '0.0',
                'mem_rate': '0.0',
                'state': 'exited',
                'type': 'share',
            }
        }
    }]

    fake_folder_status = [{
        'utility': '1.00',
        'used': '33886208',
        'subshare': True,
        'share': False,
        'worm': '',
        'free': '321931374592',
        'fsType': 'xfs',
        'owner': 'A',
        'readOnly': False,
        'modifyTime': '2017-04-27 16:16',
        'directory': '/share-pool-01/LV-1',
        'volumeId': '6541BAFB2E6C57B6',
        'mounted': True,
        'size': '321965260800'}, {
        'utility': '1.00',
        'used': '33779712',
        'subshare': False,
        'share': False,
        'worm': '',
        'free': '107287973888',
        'fsType': 'xfs',
        'owner': 'A',
        'readOnly': False,
        'modifyTime': '2017-04-27 15:45',
        'directory': '/share-pool-02/LV-1',
        'volumeId': '147A8FB67DA39914',
        'mounted': True,
        'size': '107321753600',
    }]

    def fake_get_channel_status(self, ch1_status='UP'):
        return [{
            'datalink': 'mgmt0',
            'status': 'UP',
            'typeConfig': 'DHCP',
            'IP': '172.27.112.125',
            'MAC': '00:d0:23:00:15:a6',
            'netmask': '255.255.240.0',
            'type': 'dhcp',
            'gateway': '172.27.127.254'}, {
            'datalink': 'CH0',
            'status': 'UP',
            'typeConfig': 'DHCP',
            'IP': self.fake_channel_ip[0],
            'MAC': '00:d0:23:80:15:a6',
            'netmask': '255.255.240.0',
            'type': 'dhcp',
            'gateway': '172.27.127.254'}, {
            'datalink': 'CH1',
            'status': ch1_status,
            'typeConfig': 'DHCP',
            'IP': self.fake_channel_ip[1],
            'MAC': '00:d0:23:40:15:a6',
            'netmask': '255.255.240.0',
            'type': 'dhcp',
            'gateway': '172.27.127.254'}, {
            'datalink': 'CH2',
            'status': 'DOWN',
            'typeConfig': 'DHCP',
            'IP': '',
            'MAC': '00:d0:23:c0:15:a6',
            'netmask': '',
            'type': '',
            'gateway': ''}, {
            'datalink': 'CH3',
            'status': 'DOWN',
            'typeConfig': 'DHCP',
            'IP': '',
            'MAC': '00:d0:23:20:15:a6',
            'netmask': '',
            'type': '',
            'gateway': '',
        }]

    fake_fquota_status = [{
        'quota': '21474836480',
        'used': '0',
        'name': 'test-folder',
        'type': 'subfolder',
        'id': '537178178'}, {
        'quota': '32212254720',
        'used': '0',
        'name': fake_share_name[0],
        'type': 'subfolder',
        'id': '805306752'}, {
        'quota': '53687091200',
        'used': '21474836480',
        'name': fake_share_name[1],
        'type': 'subfolder',
        'id': '69'}, {
        'quota': '94091997184',
        'used': '0',
        'type': 'subfolder',
        'id': '70',
        "name": 'test-folder-02'
    }]

    fake_fquota_status_with_no_settings = []

    def fake_get_share_status_nfs(self, status=False):
        fake_share_status_nfs = [{
            'ftp': False,
            'cifs': False,
            'oss': False,
            'sftp': False,
            'nfs': status,
            'directory': '/LV-1/share-pool-01/' + self.fake_share_name[0],
            'exist': True,
            'afp': False,
            'webdav': False
        }]
        if status:
            fake_share_status_nfs[0]['nfs_detail'] = {
                'hostList': [{
                    'uid': '65534',
                    'insecure': 'insecure',
                    'squash': 'all',
                    'access': 'ro',
                    'host': '*',
                    'gid': '65534',
                    'mode': 'async',
                    'no_subtree_check': 'no_subtree_check',
                }]
            }
        return fake_share_status_nfs

    def fake_get_share_status_cifs(self, status=False):
        fake_share_status_cifs = [{
            'ftp': False,
            'cifs': status,
            'oss': False,
            'sftp': False,
            'nfs': False,
            'directory': '/share-pool-01/LV-1/' + self.fake_share_name[1],
            'exist': True,
            'afp': False,
            'webdav': False
        }]
        if status:
            fake_share_status_cifs[0]['cifs_detail'] = {
                'available': True,
                'encrypt': False,
                'description': '',
                'sharename': 'cifs-01',
                'failover': '',
                'AIO': True,
                'priv': 'None',
                'recycle_bin': False,
                'ABE': True,
            }
        return fake_share_status_cifs

    fake_subfolder_data = [{
        'size': '6',
        'index': '34',
        'description': '',
        'encryption': '',
        'isEnd': False,
        'share': False,
        'volumeId': '6541BAFB2E6C57B6',
        'quota': '',
        'modifyTime': '2017-04-06 11:35',
        'owner': 'A',
        'path': '/share-pool-01/LV-1/UserHome',
        'subshare': True,
        'type': 'subfolder',
        'empty': False,
        'name': 'UserHome'}, {
        'size': '6',
        'index': '39',
        'description': '',
        'encryption': '',
        'isEnd': False,
        'share': False,
        'volumeId': '6541BAFB2E6C57B6',
        'quota': '21474836480',
        'modifyTime': '2017-04-27 15:44',
        'owner': 'A',
        'path': '/share-pool-01/LV-1/test-folder',
        'subshare': False,
        'type': 'subfolder',
        'empty': True,
        'name': 'test-folder'}, {
        'size': '6',
        'index': '45',
        'description': '',
        'encryption': '',
        'isEnd': False,
        'share': True,
        'volumeId': '6541BAFB2E6C57B6',
        'quota': '32212254720',
        'modifyTime': '2017-04-27 16:15',
        'owner': 'A',
        'path': '/share-pool-01/LV-1/' + fake_share_name[0],
        'subshare': False,
        'type': 'subfolder',
        'empty': True,
        'name': fake_share_name[0]}, {
        'size': '6',
        'index': '512',
        'description': '',
        'encryption': '',
        'isEnd': True,
        'share': True,
        'volumeId': '6541BAFB2E6C57B6',
        'quota': '53687091200',
        'modifyTime': '2017-04-27 16:16',
        'owner': 'A',
        'path': '/share-pool-01/LV-1/' + fake_share_name[1],
        'subshare': False,
        'type': 'subfolder',
        'empty': True,
        'name': fake_share_name[1]}, {
        'size': '6',
        'index': '777',
        'description': '',
        'encryption': '',
        'isEnd': False,
        'share': False,
        'volumeId': '6541BAFB2E6C57B6',
        'quota': '94091997184',
        'modifyTime': '2017-04-28 15:44',
        'owner': 'A',
        'path': '/share-pool-01/LV-1/test-folder-02',
        'subshare': False,
        'type': 'subfolder',
        'empty': True,
        'name': 'test-folder-02'
    }]

    fake_cifs_user_list = [{
        'Superuser': 'No',
        'Group': 'users',
        'Description': '',
        'Quota': 'none',
        'PWD Expiry Date': '2291-01-19',
        'Home Directory': '/share-pool-01/LV-1/UserHome/user01',
        'UID': '100001',
        'Type': 'Local',
        'Name': 'user01'}, {
        'Superuser': 'No',
        'Group': 'users',
        'Description': '',
        'Quota': 'none',
        'PWD Expiry Date': '2017-08-07',
        'Home Directory': '/share-pool-01/LV-1/UserHome/user02',
        'UID': '100002',
        'Type': 'Local',
        'Name': 'user02'
    }]

    fake_share_status_nfs_with_rules = [{
        'ftp': False,
        'cifs': False,
        'oss': False,
        'sftp': False,
        'nfs': True,
        'directory': '/share-pool-01/LV-1/' + fake_share_name[0],
        'exist': True,
        'nfs_detail': {
            'hostList': [{
                'uid': '65534',
                'insecure': 'insecure',
                'squash': 'all',
                'access': 'ro',
                'host': '*',
                'gid': '65534',
                'mode': 'async',
                'no_subtree_check':
                'no_subtree_check'}, {
                'uid': '65534',
                'insecure': 'insecure',
                'squash': 'all',
                'access': 'rw',
                'host': '172.27.1.1',
                'gid': '65534',
                'mode': 'async',
                'no_subtree_check': 'no_subtree_check'}, {
                'uid': '65534',
                'insecure': 'insecure',
                'squash': 'all',
                'access': 'rw',
                'host': '172.27.1.2',
                'gid': '65534',
                'mode': 'async',
                'no_subtree_check': 'no_subtree_check'}]
        },
        'afp': False,
        'webdav': False,
    }]

    fake_share_status_cifs_with_rules = [
        {
            'permission': {
                'Read': True,
                'Write': True,
                'Execute': True},
            'type': 'user',
            'id': '100001',
            'name': 'user01'
        }, {
            'permission': {
                'Read': True,
                'Write': False,
                'Execute': True},
            'type': 'user',
            'id': '100002',
            'name': 'user02'
        }, {
            'permission': {
                'Read': True,
                'Write': False,
                'Execute': True},
            'type': 'group@',
            'id': '100',
            'name': 'users'
        }, {
            'permission': {
                'Read': True,
                'Write': False,
                'Execute': True},
            'type': 'other@',
            'id': '',
            'name': ''
        }
    ]
