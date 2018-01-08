# Copyright (c) 2016 QNAP Systems, Inc.
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

FAKE_RES_DETAIL_DATA_LOGIN = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <authSid><![CDATA[fakeSid]]></authSid>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_ES_1_1_1 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[ES1640dc]]></displayModelName>
            <internalModelName><![CDATA[ES1640dc]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[1.1.1]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_ES_1_1_3 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[ES1640dc]]></displayModelName>
            <internalModelName><![CDATA[ES1640dc]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[1.1.3]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TS_4_0_0 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TS-870U]]></displayModelName>
            <internalModelName><![CDATA[TS-870U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[4.0.0]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TS_4_3_0 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TS-870U]]></displayModelName>
            <internalModelName><![CDATA[TS-870U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[4.3.0]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_TS_4_0_0 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TES-1885U]]></displayModelName>
            <internalModelName><![CDATA[TS-1885U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[4.0.0]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_TS_4_3_0 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TES-1885U]]></displayModelName>
            <internalModelName><![CDATA[TS-1885U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[4.3.0]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_ES_1_1_1 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TES-1885U]]></displayModelName>
            <internalModelName><![CDATA[ES-1885U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[1.1.1]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_ES_1_1_3 = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TES-1885U]]></displayModelName>
            <internalModelName><![CDATA[ES-1885U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[1.1.3]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GETBASIC_INFO_ERROR = """
    <QDocRoot version="1.0">
        <model>
            <displayModelName><![CDATA[TTS-1885U]]></displayModelName>
            <internalModelName><![CDATA[TTS-1885U]]></internalModelName>
        </model>
        <firmware>
            <version><![CDATA[1.1.3]]></version>
        </firmware>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_SHARE_INFO = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <Volume_Info>
            <row>
                <vol_no><![CDATA[fakeNo]]></vol_no>
                <vol_label><![CDATA[fakeShareName]]></vol_label>
            </row>
        </Volume_Info>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_VOLUME_INFO = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <Volume_Info>
            <row>
                <vol_no><![CDATA[fakeNo]]></vol_no>
                <size><![CDATA[10]]></size>
                <vol_mount_path>fakeMountPath</vol_mount_path>
                <dedup><![CDATA[off]]></dedup>
                <compression><![CDATA[1]]></compression>
                <thin_pro><![CDATA[1]]></thin_pro>
                <cache><![CDATA[0]]></cache>
            </row>
        </Volume_Info>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_SNAPSHOT = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <SnapshotList>
            <row>
                <snapshot_id><![CDATA[fakeSnapshotId]]></snapshot_id>
                <snapshot_name><![CDATA[fakeSnapshotName]]></snapshot_name>
            </row>
        </SnapshotList>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_SPECIFIC_POOL_INFO = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <Pool_Index>
            <row>
                <poolIndex><![CDATA[fakePoolIndex]]></poolIndex>
                <poolID><![CDATA[fakePoolId]]></poolID>
                <pool_status><![CDATA[0]]></pool_status>
                <capacity_bytes><![CDATA[930213412209]]></capacity_bytes>
                <allocated_bytes><![CDATA[1480470528]]></allocated_bytes>
                <freesize_bytes><![CDATA[928732941681]]></freesize_bytes>
                <lun_meta_reserve_ratio><![CDATA[0.0315]]></lun_meta_reserve_ratio>
                <pool_capacity><![CDATA[866 GB]]></pool_capacity>
                <pool_allocated><![CDATA[1.38 GB]]></pool_allocated>
                <pool_freesize><![CDATA[865 GB]]></pool_freesize>
                <pool_threshold><![CDATA[80 %]]></pool_threshold>
                <pool_used><![CDATA[0 %]]></pool_used>
                <pool_available><![CDATA[100 %]]></pool_available>
                <pool_owner><![CDATA[SCA]]></pool_owner>
                <pool_type><![CDATA[mirror]]></pool_type>
                <pool_dedup><![CDATA[1.00]]></pool_dedup>
                <pool_bound><![CDATA[0]]></pool_bound>
                <pool_progress><![CDATA[0]]></pool_progress>
                <pool_scrub><![CDATA[0]]></pool_scrub>
            </row>
        </Pool_Index>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GET_HOST_LIST = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <host_list>
            <host>
                <index><![CDATA[fakeHostIndex]]></index>
                <hostid><![CDATA[fakeHostId]]></hostid>
                <name><![CDATA[manila-fakeHostName]]></name>
                <netaddrs>
                    <ipv4>
                        <![CDATA[fakeIp]]>
                    </ipv4>
                </netaddrs>
            </host>
        </host_list>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_CREATE_SHARE = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <func>
            <ownContent>
                <volumeList>
                    <volume>
                        <volumeStatus><![CDATA[fakeStatus]]></volumeStatus>
                        <volumeLabel><![CDATA[fakeLabel]]></volumeLabel>
                        <volumeValue><![CDATA[faleValue]]></volumeValue>
                    </volume>
                </volumeList>
            </ownContent>
        </func>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_ES_RET_CODE_NEGATIVE = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[-1]]></ES_RET_CODE>
    </QDocRoot>"""


FAKE_RES_DETAIL_DATA_RESULT_NEGATIVE = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <result><![CDATA[-1]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_AUTHPASS_FAIL = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[0]]></authPassed>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_DELETE_SHARE = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <result>0</result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_DELETE_SNAPSHOT = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <result>0</result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_DELETE_SNAPSHOT_SNAPSHOT_NOT_EXIST = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <result>-206021</result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_DELETE_SNAPSHOT_SHARE_NOT_EXIST = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <result>-200005</result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GET_HOST_LIST_API = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <content>
            <host_list>
                <host>
                    <index><![CDATA[fakeHostIndex]]></index>
                    <hostid><![CDATA[fakeHostId]]></hostid>
                    <name><![CDATA[manila-hst-123]]></name>
                    <netaddrs>
                        <ipv4>
                            <![CDATA[fakeIp]]>
                        </ipv4>
                    </netaddrs>
                </host>
            </host_list>
        </content>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_GET_NO_HOST_LIST_API = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
        <content>
        </content>
        <result><![CDATA[0]]></result>
    </QDocRoot>"""

FAKE_RES_DETAIL_DATA_CREATE_SNAPSHOT = """
    <QDocRoot version="1.0">
        <authPassed><![CDATA[1]]></authPassed>
        <ES_RET_CODE><![CDATA[1]]></ES_RET_CODE>
    </QDocRoot>"""


class SnapshotClass(object):
    """Snapshot Class."""

    size = 0
    provider_location = 'fakeShareName@fakeSnapshotName'

    def __init__(self, size, provider_location=None):
        """Init."""
        self.size = size
        self.provider_location = provider_location

    def get(self, provider_location):
        """Get function."""
        return self.provider_location

    def __getitem__(self, arg):
        """Getitem."""
        return {
            'display_name': 'fakeSnapshotDisplayName',
            'id': 'fakeSnapshotId',
            'share': {'share_id': 'fakeShareId', 'id': 'fakeId'},
            'share_instance': {'share_id': 'fakeShareId', 'id': 'fakeId'},
            'size': self.size,
            'share_instance_id': 'fakeShareId'
        }[arg]

    def __setitem__(self, key, value):
        """Setitem."""
        if key == 'provider_location':
            self.provider_location = value


class ShareNfsClass(object):
    """Share Class."""

    share_proto = 'NFS'
    id = ''
    size = 0

    def __init__(self, share_id, size):
        """Init."""
        self.id = share_id
        self.size = size

    def __getitem__(self, arg):
        """Getitem."""
        return {
            'share_proto': self.share_proto,
            'id': self.id,
            'display_name': 'fakeDisplayName',
            'export_locations': [{'path': '1.2.3.4:/share/fakeShareName'}],
            'host': 'QnapShareDriver',
            'size': self.size
        }[arg]

    def __setitem__(self, key, value):
        """Setitem."""
        if key == 'share_proto':
            self.share_proto = value


class ShareCifsClass(object):
    """Share Class."""

    share_proto = 'CIFS'
    id = ''
    size = 0

    def __init__(self, share_id, size):
        """Init."""
        self.id = share_id
        self.size = size

    def __getitem__(self, arg):
        """Getitem."""
        return {
            'share_proto': self.share_proto,
            'id': self.id,
            'display_name': 'fakeDisplayName',
            'export_locations': [{'path': '\\\\1.2.3.4\\fakeShareName'}],
            'host': 'QnapShareDriver',
            'size': self.size
        }[arg]

    def __setitem__(self, key, value):
        """Setitem."""
        if key == 'share_proto':
            self.share_proto = value


class AccessClass(object):
    """Access Class."""

    access_type = 'fakeAccessType'
    access_level = 'ro'
    access_to = 'fakeIp'

    def __init__(self, access_type, access_level, access_to):
        """Init."""
        self.access_type = access_type
        self.access_level = access_level
        self.access_to = access_to

    def __getitem__(self, arg):
        """Getitem."""
        return {
            'access_type': self.access_type,
            'access_level': self.access_level,
            'access_to': self.access_to,
        }[arg]


class FakeGetBasicInfoResponseEs_1_1_1(object):
    """Fake GetBasicInfo response from ES nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_ES_1_1_1


class FakeGetBasicInfoResponseEs_1_1_3(object):
    """Fake GetBasicInfo response from ES nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_ES_1_1_3


class FakeGetBasicInfoResponseTs_4_0_0(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TS_4_0_0


class FakeGetBasicInfoResponseTs_4_3_0(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TS_4_3_0


class FakeGetBasicInfoResponseTesTs_4_0_0(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_TS_4_0_0


class FakeGetBasicInfoResponseTesTs_4_3_0(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_TS_4_3_0


class FakeGetBasicInfoResponseTesEs_1_1_1(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_ES_1_1_1


class FakeGetBasicInfoResponseTesEs_1_1_3(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_TES_ES_1_1_3


class FakeGetBasicInfoResponseError(object):
    """Fake GetBasicInfoTS response from TS nas."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GETBASIC_INFO_ERROR


class FakeCreateShareResponse(object):
    """Fake login response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_CREATE_SHARE


class FakeDeleteShareResponse(object):
    """Fake login response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_DELETE_SHARE


class FakeDeleteSnapshotResponse(object):
    """Fake delete snapshot response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_DELETE_SNAPSHOT


class FakeDeleteSnapshotResponseSnapshotNotExist(object):
    """Fake delete snapshot response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_DELETE_SNAPSHOT_SNAPSHOT_NOT_EXIST


class FakeDeleteSnapshotResponseShareNotExist(object):
    """Fake delete snapshot response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_DELETE_SNAPSHOT_SHARE_NOT_EXIST


class FakeGetHostListResponse(object):
    """Fake host info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GET_HOST_LIST_API


class FakeGetNoHostListResponse(object):
    """Fake host info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_GET_NO_HOST_LIST_API


class FakeAuthPassFailResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_AUTHPASS_FAIL


class FakeEsResCodeNegativeResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_ES_RET_CODE_NEGATIVE


class FakeResultNegativeResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_RESULT_NEGATIVE


class FakeLoginResponse(object):
    """Fake login response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_LOGIN


class FakeSpecificPoolInfoResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_SPECIFIC_POOL_INFO


class FakeShareInfoResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_SHARE_INFO


class FakeSnapshotInfoResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_SNAPSHOT


class FakeSpecificVolInfoResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_VOLUME_INFO


class FakeCreateSnapshotResponse(object):
    """Fake pool info response."""

    status = 'fackStatus'

    def read(self):
        """Mock response.read."""
        return FAKE_RES_DETAIL_DATA_CREATE_SNAPSHOT
