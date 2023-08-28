# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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

from unittest import mock

from lxml import etree
import requests

from manila.share.drivers.netapp.dataontap.client import api


CONNECTION_INFO = {
    'hostname': 'hostname',
    'transport_type': 'https',
    'ssl_cert_path': '/etc/ssl/certs/',
    'port': 443,
    'username': 'admin',
    'password': 'passw0rd',
    'api_trace_pattern': '(.*)',
    'client_api': 'rest',
    'async_rest_timeout': 60,
}

NO_SNAPRESTORE_LICENSE = '"SnapRestore" is not licensed in the cluster.'
FAKE_UUID = 'b32bab78-82be-11ec-a8a3-0242ac120002'
CLUSTER_NAME = 'fake_cluster'
REMOTE_CLUSTER_NAME = 'fake_cluster_2'
CLUSTER_ADDRESS_1 = 'fake_cluster_address'
CLUSTER_ADDRESS_2 = 'fake_cluster_address_2'
VERSION = 'NetApp Release 8.2.1 Cluster-Mode: Fri Mar 21 14:25:07 PDT 2014'
VERSION_NO_DARE = 'NetApp Release 9.1.0: Tue May 10 19:30:23 2016 <1no-DARE>'
VERSION_TUPLE = (9, 1, 0)
NODE_NAME = 'fake_node1'
NODE_NAMES = ('fake_node1', 'fake_node2')
VSERVER_NAME = 'fake_vserver'
VSERVER_NAME_2 = 'fake_vserver_2'
VSERVER_PEER_NAME = 'fake_vserver_peer'
VSERVER_PEER_STATE = 'peered'
ADMIN_VSERVER_NAME = 'fake_admin_vserver'
NODE_VSERVER_NAME = 'fake_node_vserver'
NFS_VERSIONS = ['nfs3', 'nfs4.0']
SECURITY_CERT_DEFAULT_EXPIRE_DAYS = 365
SECURITY_CERT_LARGE_EXPIRE_DAYS = 3652
ROOT_AGGREGATE_NAMES = ('root_aggr1', 'root_aggr2')
ROOT_VOLUME_AGGREGATE_NAME = 'fake_root_aggr'
ROOT_VOLUME_NAME = 'fake_root_volume'
VOLUME_NAMES = ('volume1', 'volume2')
SHARE_AGGREGATE_NAME = 'fake_aggr1'
SHARE_AGGREGATE_NAMES = ('fake_aggr1', 'fake_aggr2')
SHARE_AGGREGATE_NAMES_LIST = ['fake_aggr1', 'fake_aggr2']
SHARE_AGGREGATE_RAID_TYPES = ('raid4', 'raid_dp')
SHARE_AGGREGATE_DISK_TYPE = 'FCAL'
SHARE_AGGREGATE_DISK_TYPES = ['SATA', 'SSD']
EFFECTIVE_TYPE = 'fake_effective_type1'
SHARE_NAME = 'fake_share'
SHARE_SIZE = '1000000000'
SHARE_NAME_2 = 'fake_share_2'
FLEXGROUP_STYLE_EXTENDED = 'flexgroup'
FLEXVOL_STYLE_EXTENDED = 'flexvol'
SNAPSHOT_NAME = 'fake_snapshot'
CG_SNAPSHOT_ID = 'fake_cg_id'
PARENT_SHARE_NAME = 'fake_parent_share'
PARENT_SNAPSHOT_NAME = 'fake_parent_snapshot'
MAX_FILES = 5000
LANGUAGE = 'fake_language'
SNAPSHOT_POLICY_NAME = 'fake_snapshot_policy'
EXPORT_POLICY_NAME = 'fake_export_policy'
DELETED_EXPORT_POLICIES = {
    VSERVER_NAME: [
        'deleted_manila_fake_policy_1',
        'deleted_manila_fake_policy_2',
    ],
    VSERVER_NAME_2: [
        'deleted_manila_fake_policy_3',
    ],
}
QOS_POLICY_GROUP_NAME = 'fake_qos_policy_group_name'
QOS_MAX_THROUGHPUT = '5000B/s'
QOS_MAX_THROUGHPUT_IOPS = '5000iops'
QOS_MAX_THROUGHPUT_NO_UNIT = 5000
QOS_MAX_THROUGHPUT_IOPS_NO_UNIT = 5000
ADAPTIVE_QOS_POLICY_GROUP_NAME = 'fake_adaptive_qos_policy_group_name'
VSERVER_TYPE_DEFAULT = 'default'
VSERVER_TYPE_DP_DEST = 'dp_destination'
VSERVER_OP_STATE_RUNNING = 'running'
VSERVER_STATE = 'running'
VSERVER_INFO = {
    'name': VSERVER_NAME,
    'subtype': VSERVER_TYPE_DEFAULT,
    'operational_state': VSERVER_OP_STATE_RUNNING,
    'state': VSERVER_STATE,
}
SNAPMIRROR_POLICY_NAME = 'fake_snapmirror_policy'
SNAPMIRROR_POLICY_TYPE = 'async_mirror'

USER_NAME = 'fake_user'

PORT = 'e0a'
VLAN = '1001'
VLAN_PORT = 'e0a-1001'
IP_ADDRESS = '10.10.10.10'
NETMASK = '255.255.255.0'
GATEWAY = '10.10.10.1'
SUBNET = '10.10.10.0/24'
NET_ALLOCATION_ID = 'fake_allocation_id'
LIF_NAME_TEMPLATE = 'os_%(net_allocation_id)s'
LIF_NAME = LIF_NAME_TEMPLATE % {'net_allocation_id': NET_ALLOCATION_ID}
IPSPACE_NAME = 'fake_ipspace'
BROADCAST_DOMAIN = 'fake_domain'
MTU = 9000
SM_SOURCE_VSERVER = 'fake_source_vserver'
SM_SOURCE_VOLUME = 'fake_source_volume'
SM_DEST_VSERVER = 'fake_destination_vserver'
SM_DEST_VOLUME = 'fake_destination_volume'
SM_SOURCE_PATH = SM_SOURCE_VSERVER + ':' + SM_SOURCE_VOLUME
SM_DEST_PATH = SM_DEST_VSERVER + ':' + SM_DEST_VOLUME


FPOLICY_POLICY_NAME = 'fake_fpolicy_name'
FPOLICY_EVENT_NAME = 'fake_fpolicy_event_name'
FPOLICY_PROTOCOL = 'cifs'
FPOLICY_FILE_OPERATIONS = 'create,write,rename'
FPOLICY_FILE_OPERATIONS_LIST = ['create', 'write', 'rename']
FPOLICY_ENGINE = 'native'
FPOLICY_EXT_TO_INCLUDE = 'avi'
FPOLICY_EXT_TO_INCLUDE_LIST = ['avi']
FPOLICY_EXT_TO_EXCLUDE = 'jpg,mp3'
FPOLICY_EXT_TO_EXCLUDE_LIST = ['jpg', 'mp3']

JOB_ID = 123
JOB_STATE = 'success'

NETWORK_INTERFACES = [{
    'interface_name': 'fake_interface',
    'address': IP_ADDRESS,
    'vserver': VSERVER_NAME,
    'netmask': NETMASK,
    'role': 'data',
    'home-node': NODE_NAME,
    'home-port': VLAN_PORT
}]

NETWORK_INTERFACES_MULTIPLE = [
    {
        'interface_name': 'fake_interface',
        'address': IP_ADDRESS,
        'vserver': VSERVER_NAME,
        'netmask': NETMASK,
        'role': 'data',
        'home-node': NODE_NAME,
        'home-port': VLAN_PORT,
    },
    {
        'interface_name': 'fake_interface_2',
        'address': '10.10.12.10',
        'vserver': VSERVER_NAME,
        'netmask': NETMASK,
        'role': 'data',
        'home-node': NODE_NAME,
        'home-port': PORT,
    }
]

IPSPACES = [{
    'uuid': 'fake_uuid',
    'ipspace': IPSPACE_NAME,
    'id': 'fake_id',
    'broadcast-domains': ['OpenStack'],
    'ports': [NODE_NAME + ':' + VLAN_PORT],
    'vservers': [
        IPSPACE_NAME,
        VSERVER_NAME,
    ]
}]

EMS_MESSAGE = {
    'computer-name': 'fake_host',
    'event-id': '0',
    'event-source': 'fake driver',
    'app-version': 'fake app version',
    'category': 'fake category',
    'event-description': 'fake description',
    'log-level': '6',
    'auto-support': 'false',
}

QOS_POLICY_GROUP = {
    'policy-group': QOS_POLICY_GROUP_NAME,
    'vserver': VSERVER_NAME,
    'max-throughput': QOS_MAX_THROUGHPUT,
    'num-workloads': 1,
}

VOLUME_AUTOSIZE_ATTRS = {
    'mode': 'off',
    'grow-threshold-percent': '85',
    'shrink-threshold-percent': '50',
    'maximum-size': '1258288',
    'minimum-size': '1048576',
}


NO_RECORDS_RESPONSE = etree.XML("""
  <results status="passed">
    <num-records>0</num-records>
  </results>
""")

PASSED_RESPONSE = etree.XML("""
  <results status="passed" />
""")

PASSED_FAILED_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <num-failed>0</num-failed>
    <num-succeeded>1</num-succeeded>
  </results>
""")

INVALID_GET_ITER_RESPONSE_NO_ATTRIBUTES = etree.XML("""
  <results status="passed">
    <num-records>1</num-records>
    <next-tag>fake_tag</next-tag>
  </results>
""")

INVALID_GET_ITER_RESPONSE_NO_RECORDS = etree.XML("""
  <results status="passed">
    <attributes-list/>
    <next-tag>fake_tag</next-tag>
  </results>
""")

VSERVER_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <vserver-info>
        <vserver-name>%(fake_vserver)s</vserver-name>
      </vserver-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'fake_vserver': VSERVER_NAME})

VSERVER_GET_ITER_RESPONSE_INFO = etree.XML("""
  <results status="passed">
    <attributes-list>
      <vserver-info>
        <operational-state>%(operational_state)s</operational-state>
        <state>%(state)s</state>
        <vserver-name>%(name)s</vserver-name>
        <vserver-subtype>%(subtype)s</vserver-subtype>
      </vserver-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % VSERVER_INFO)

VSERVER_GET_ROOT_VOLUME_NAME_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <vserver-info>
        <root-volume>%(root_volume)s</root-volume>
        <vserver-name>%(fake_vserver)s</vserver-name>
      </vserver-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'root_volume': ROOT_VOLUME_NAME, 'fake_vserver': VSERVER_NAME})

VSERVER_GET_IPSPACE_NAME_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <vserver-info>
        <ipspace>%(ipspace)s</ipspace>
        <vserver-name>%(fake_vserver)s</vserver-name>
      </vserver-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'ipspace': IPSPACE_NAME, 'fake_vserver': VSERVER_NAME})

VSERVER_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes>
      <vserver-info>
        <aggr-list>
          <aggr-name>%(aggr1)s</aggr-name>
          <aggr-name>%(aggr2)s</aggr-name>
        </aggr-list>
        <vserver-aggr-info-list>
          <vserver-aggr-info>
            <aggr-availsize>45678592</aggr-availsize>
            <aggr-name>%(aggr1)s</aggr-name>
          </vserver-aggr-info>
          <vserver-aggr-info>
            <aggr-availsize>6448431104</aggr-availsize>
            <aggr-name>%(aggr2)s</aggr-name>
          </vserver-aggr-info>
        </vserver-aggr-info-list>
        <vserver-name>%(vserver)s</vserver-name>
      </vserver-info>
    </attributes>
  </results>
""" % {
    'vserver': VSERVER_NAME,
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
})

SECURITY_CERT_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <certificate-info>
        <vserver>%(vserver)s</vserver>
        <serial-number>12345</serial-number>
      </certificate-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'vserver': VSERVER_NAME})

VSERVER_DATA_LIST_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <vserver-info>
        <vserver-name>%(vserver)s</vserver-name>
        <vserver-type>data</vserver-type>
      </vserver-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'vserver': VSERVER_NAME})

VSERVER_AGGREGATES = {
    SHARE_AGGREGATE_NAMES[0]: {
        'available': 45678592,
    },
    SHARE_AGGREGATE_NAMES[1]: {
        'available': 6448431104,
    },
}

VSERVER_GET_RESPONSE_NO_AGGREGATES = etree.XML("""
  <results status="passed">
    <attributes>
      <vserver-info>
        <vserver-name>%(vserver)s</vserver-name>
      </vserver-info>
    </attributes>
  </results>
""" % {'vserver': VSERVER_NAME})

ONTAPI_VERSION_RESPONSE = etree.XML("""
  <results status="passed">
    <major-version>1</major-version>
    <minor-version>19</minor-version>
  </results>
""")

SYSTEM_GET_VERSION_RESPONSE = etree.XML("""
  <results status="passed">
    <build-timestamp>1395426307</build-timestamp>
    <is-clustered>true</is-clustered>
    <version>%(version)s</version>
    <version-tuple>
      <system-version-tuple>
        <generation>8</generation>
        <major>2</major>
        <minor>1</minor>
      </system-version-tuple>
    </version-tuple>
  </results>
""" % {'version': VERSION})

LICENSE_V2_LIST_INFO_RESPONSE = etree.XML("""
  <results status="passed">
    <licenses>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>Cluster Base License</description>
        <legacy>false</legacy>
        <owner>cluster3</owner>
        <package>base</package>
        <serial-number>1-80-000008</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>NFS License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>nfs</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>CIFS License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>cifs</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>iSCSI License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>iscsi</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>FCP License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>fcp</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>SnapRestore License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>snaprestore</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>SnapMirror License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>snapmirror</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>FlexClone License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>flexclone</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
      <license-v2-info>
        <customer-id>none</customer-id>
        <description>SnapVault License</description>
        <legacy>false</legacy>
        <owner>cluster3-01</owner>
        <package>snapvault</package>
        <serial-number>1-81-0000000000000004082368507</serial-number>
        <type>license</type>
      </license-v2-info>
    </licenses>
  </results>
""")

LICENSES = (
    'base', 'cifs', 'fcp', 'flexclone', 'iscsi', 'nfs', 'snapmirror',
    'snaprestore', 'snapvault'
)

VOLUME_COUNT_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>vol0</name>
          <owning-vserver-name>cluster3-01</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(root_volume)s</name>
          <owning-vserver-name>%(fake_vserver)s</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {'root_volume': ROOT_VOLUME_NAME, 'fake_vserver': VSERVER_NAME})

CIFS_SECURITY_SERVICE = {
    'type': 'active_directory',
    'password': 'fake_password',
    'user': 'fake_user',
    'ou': 'fake_ou',
    'domain': 'fake_domain',
    'dns_ip': 'fake_dns_ip',
    'server': 'fake_server',
    'default_ad_site': None,
}

CIFS_SECURITY_SERVICE_2 = {
    'type': 'active_directory',
    'password': 'fake_password_2',
    'user': 'fake_user_2',
    'ou': 'fake_ou_2',
    'domain': 'fake_domain_2',
    'dns_ip': 'fake_dns_ip_2',
    'server': 'fake_server_2',
    'default_ad_site': None,
}

CIFS_SECURITY_SERVICE_3 = {
    'type': 'active_directory',
    'password': 'fake_password_3',
    'user': 'fake_user_3',
    'ou': 'fake_ou_3',
    'domain': 'fake_domain_3',
    'dns_ip': 'fake_dns_ip_3',
    'default_ad_site': 'fake_default_ad_site_3',
    'server': None,
}

CIFS_SECURITY_SERVICE_4 = {
    'type': 'active_directory',
    'password': 'fake_password_4',
    'user': 'fake_user_4',
    'ou': 'fake_ou_4',
    'domain': 'fake_domain_4',
    'dns_ip': 'fake_dns_ip_4',
    'default_ad_site': 'fake_default_ad_site_4',
    'server': None,
}

LDAP_LINUX_SECURITY_SERVICE = {
    'id': 'fake_id',
    'type': 'ldap',
    'user': 'fake_user',
    'password': 'fake_password',
    'server': 'fake_server',
    'ou': 'fake_ou',
    'dns_ip': None,
    'domain': None
}

LDAP_AD_SECURITY_SERVICE = {
    'id': 'fake_id',
    'type': 'ldap',
    'user': 'fake_user',
    'password': 'fake_password',
    'domain': 'fake_domain',
    'ou': 'fake_ou',
    'dns_ip': 'fake_dns_ip',
    'server': None,
}

LDAP_AD_SECURITY_SERVICE_WITH_SERVER = {
    'id': 'fake_id',
    'type': 'ldap',
    'user': 'fake_user',
    'password': 'fake_password',
    'domain': None,
    'ou': 'fake_ou',
    'dns_ip': 'fake_dns_ip',
    'server': '10.10.10.1',
}

KERBEROS_SECURITY_SERVICE = {
    'type': 'kerberos',
    'password': 'fake_password',
    'user': 'fake_user',
    'server': 'fake_server',
    'id': 'fake_id',
    'domain': 'fake_domain',
    'dns_ip': 'fake_dns_ip',
}

KERBEROS_SERVICE_PRINCIPAL_NAME = 'nfs/fake-vserver.fake_domain@FAKE_DOMAIN'

INVALID_SECURITY_SERVICE = {
    'type': 'fake',
}

SYSTEM_NODE_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <node-details-info>
        <node>%s</node>
      </node-details-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % NODE_NAME)

SECUTITY_KEY_MANAGER_NVE_SUPPORT_RESPONSE_TRUE = etree.XML("""
  <results status="passed">
    <vol-encryption-supported>true</vol-encryption-supported>
  </results>
""")

SECUTITY_KEY_MANAGER_NVE_SUPPORT_RESPONSE_FALSE = etree.XML("""
  <results status="passed">
    <vol-encryption-supported>false</vol-encryption-supported>
  </results>
""")

NET_PORT_GET_RESPONSE_NO_VLAN = etree.XML("""
  <results status="passed">
    <attributes>
      <net-port-info>
        <administrative-duplex>auto</administrative-duplex>
        <administrative-flowcontrol>full</administrative-flowcontrol>
        <administrative-speed>auto</administrative-speed>f
        <broadcast-domain>%(domain)s</broadcast-domain>
        <health-status>healthy</health-status>
        <ignore-health-status>false</ignore-health-status>
        <ipspace>%(ipspace)s</ipspace>
        <is-administrative-auto-negotiate>true</is-administrative-auto-negotiate>
        <is-administrative-up>true</is-administrative-up>
        <is-operational-auto-negotiate>true</is-operational-auto-negotiate>
        <link-status>up</link-status>
        <mac-address>00:0c:29:fc:04:f7</mac-address>
        <mtu>1500</mtu>
        <mtu-admin>1500</mtu-admin>
        <node>%(node_name)s</node>
        <operational-duplex>full</operational-duplex>
        <operational-flowcontrol>receive</operational-flowcontrol>
        <operational-speed>1000</operational-speed>
        <port>%(port)s</port>
        <port-type>physical</port-type>
        <role>data</role>
      </net-port-info>
    </attributes>
  </results>
""" % {'domain': BROADCAST_DOMAIN,
       'ipspace': IPSPACE_NAME,
       'node_name': NODE_NAME,
       'port': PORT})

NET_PORT_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes>
      <net-port-info>
        <administrative-duplex>auto</administrative-duplex>
        <administrative-flowcontrol>full</administrative-flowcontrol>
        <administrative-speed>auto</administrative-speed>
        <health-status>healthy</health-status>
        <ignore-health-status>false</ignore-health-status>
        <ipspace>%(ipspace)s</ipspace>
        <is-administrative-auto-negotiate>true</is-administrative-auto-negotiate>
        <is-administrative-up>true</is-administrative-up>
        <is-operational-auto-negotiate>true</is-operational-auto-negotiate>
        <link-status>up</link-status>
        <mac-address>00:0c:29:fc:04:f7</mac-address>
        <mtu>1500</mtu>
        <mtu-admin>1500</mtu-admin>
        <node>%(node_name)s</node>
        <operational-duplex>full</operational-duplex>
        <operational-flowcontrol>receive</operational-flowcontrol>
        <operational-speed>1000</operational-speed>
        <port>%(port)s-%(vlan)s</port>
        <port-type>vlan</port-type>
        <role>data</role>
        <vlan-id>%(vlan)s</vlan-id>
        <vlan-node>%(node_name)s</vlan-node>
        <vlan-port>%(port)s</vlan-port>
      </net-port-info>
    </attributes>
  </results>
""" % {'ipspace': IPSPACE_NAME,
       'node_name': NODE_NAME,
       'port': PORT,
       'vlan': VLAN})

NET_PORT_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-port-info>
        <administrative-duplex>full</administrative-duplex>
        <administrative-flowcontrol>full</administrative-flowcontrol>
        <administrative-speed>auto</administrative-speed>
        <is-administrative-auto-negotiate>true</is-administrative-auto-negotiate>
        <is-administrative-up>true</is-administrative-up>
        <is-operational-auto-negotiate>true</is-operational-auto-negotiate>
        <link-status>up</link-status>
        <mac-address>00:0c:29:fc:04:d9</mac-address>
        <mtu>1500</mtu>
        <node>%(node_name)s</node>
        <operational-duplex>full</operational-duplex>
        <operational-flowcontrol>none</operational-flowcontrol>
        <operational-speed>10</operational-speed>
        <port>e0a</port>
        <port-type>physical</port-type>
        <role>data</role>
      </net-port-info>
      <net-port-info>
        <administrative-duplex>full</administrative-duplex>
        <administrative-flowcontrol>full</administrative-flowcontrol>
        <administrative-speed>auto</administrative-speed>
        <is-administrative-auto-negotiate>true</is-administrative-auto-negotiate>
        <is-administrative-up>true</is-administrative-up>
        <is-operational-auto-negotiate>true</is-operational-auto-negotiate>
        <link-status>up</link-status>
        <mac-address>00:0c:29:fc:04:e3</mac-address>
        <mtu>1500</mtu>
        <node>%(node_name)s</node>
        <operational-duplex>full</operational-duplex>
        <operational-flowcontrol>none</operational-flowcontrol>
        <operational-speed>100</operational-speed>
        <port>e0b</port>
        <port-type>physical</port-type>
        <role>data</role>
      </net-port-info>
      <net-port-info>
        <administrative-duplex>full</administrative-duplex>
        <administrative-flowcontrol>full</administrative-flowcontrol>
        <administrative-speed>auto</administrative-speed>
        <is-administrative-auto-negotiate>true</is-administrative-auto-negotiate>
        <is-administrative-up>true</is-administrative-up>
        <is-operational-auto-negotiate>true</is-operational-auto-negotiate>
        <link-status>up</link-status>
        <mac-address>00:0c:29:fc:04:ed</mac-address>
        <mtu>1500</mtu>
        <node>%(node_name)s</node>
        <operational-duplex>full</operational-duplex>
        <operational-flowcontrol>none</operational-flowcontrol>
        <operational-speed>1000</operational-speed>
        <port>e0c</port>
        <port-type>physical</port-type>
        <role>data</role>
      </net-port-info>
      <net-port-info>
        <administrative-duplex>full</administrative-duplex>
        <administrative-flowcontrol>full</administrative-flowcontrol>
        <administrative-speed>auto</administrative-speed>
        <is-administrative-auto-negotiate>true</is-administrative-auto-negotiate>
        <is-administrative-up>true</is-administrative-up>
        <is-operational-auto-negotiate>true</is-operational-auto-negotiate>
        <link-status>up</link-status>
        <mac-address>00:0c:29:fc:04:f7</mac-address>
        <mtu>1500</mtu>
        <node>%(node_name)s</node>
        <operational-duplex>full</operational-duplex>
        <operational-flowcontrol>none</operational-flowcontrol>
        <operational-speed>10000</operational-speed>
        <port>e0d</port>
        <port-type>physical</port-type>
        <role>data</role>
      </net-port-info>
    </attributes-list>
    <num-records>4</num-records>
  </results>
""" % {'node_name': NODE_NAME})

SPEED_SORTED_PORTS = (
    {'node': NODE_NAME, 'port': 'e0d', 'speed': '10000'},
    {'node': NODE_NAME, 'port': 'e0c', 'speed': '1000'},
    {'node': NODE_NAME, 'port': 'e0b', 'speed': '100'},
    {'node': NODE_NAME, 'port': 'e0a', 'speed': '10'},
)
PORT_NAMES = ('e0a', 'e0b', 'e0c', 'e0d')
SPEED_SORTED_PORT_NAMES = ('e0d', 'e0c', 'e0b', 'e0a')

UNSORTED_PORTS_ALL_SPEEDS = (
    {'node': NODE_NAME, 'port': 'port6', 'speed': 'undef'},
    {'node': NODE_NAME, 'port': 'port3', 'speed': '100'},
    {'node': NODE_NAME, 'port': 'port1', 'speed': '10000'},
    {'node': NODE_NAME, 'port': 'port4', 'speed': '10'},
    {'node': NODE_NAME, 'port': 'port7'},
    {'node': NODE_NAME, 'port': 'port2', 'speed': '1000'},
    {'node': NODE_NAME, 'port': 'port5', 'speed': 'auto'},
)

SORTED_PORTS_ALL_SPEEDS = (
    {'node': NODE_NAME, 'port': 'port1', 'speed': '10000'},
    {'node': NODE_NAME, 'port': 'port2', 'speed': '1000'},
    {'node': NODE_NAME, 'port': 'port3', 'speed': '100'},
    {'node': NODE_NAME, 'port': 'port4', 'speed': '10'},
    {'node': NODE_NAME, 'port': 'port5', 'speed': 'auto'},
    {'node': NODE_NAME, 'port': 'port6', 'speed': 'undef'},
    {'node': NODE_NAME, 'port': 'port7'},
)

NET_PORT_GET_ITER_BROADCAST_DOMAIN_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-port-info>
        <ipspace>%(ipspace)s</ipspace>
        <broadcast-domain>%(domain)s</broadcast-domain>
        <node>%(node)s</node>
        <port>%(port)s</port>
      </net-port-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'domain': BROADCAST_DOMAIN,
    'node': NODE_NAME,
    'port': PORT,
    'ipspace': IPSPACE_NAME,
})

NET_PORT_GET_ITER_BROADCAST_DOMAIN_MISSING_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-port-info>
        <ipspace>%(ipspace)s</ipspace>
        <node>%(node)s</node>
        <port>%(port)s</port>
      </net-port-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'node': NODE_NAME, 'port': PORT, 'ipspace': IPSPACE_NAME})

NET_PORT_BROADCAST_DOMAIN_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-port-broadcast-domain-info>
        <broadcast-domain>%(domain)s</broadcast-domain>
        <ipspace>%(ipspace)s</ipspace>
      </net-port-broadcast-domain-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'domain': BROADCAST_DOMAIN, 'ipspace': IPSPACE_NAME})

NET_IPSPACES_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-ipspaces-info>
        <broadcast-domains>
          <broadcast-domain-name>OpenStack</broadcast-domain-name>
        </broadcast-domains>
        <id>fake_id</id>
        <ipspace>%(ipspace)s</ipspace>
        <ports>
          <net-qualified-port-name>%(node)s:%(port)s</net-qualified-port-name>
        </ports>
        <uuid>fake_uuid</uuid>
        <vservers>
          <vserver-name>%(ipspace)s</vserver-name>
          <vserver-name>%(vserver)s</vserver-name>
        </vservers>
      </net-ipspaces-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'ipspace': IPSPACE_NAME,
    'node': NODE_NAME,
    'port': VLAN_PORT,
    'vserver': VSERVER_NAME
})

NET_INTERFACE_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-interface-info>
        <address>192.168.228.42</address>
        <address-family>ipv4</address-family>
        <administrative-status>up</administrative-status>
        <current-node>%(node)s</current-node>
        <current-port>e0c</current-port>
        <data-protocols>
          <data-protocol>none</data-protocol>
        </data-protocols>
        <dns-domain-name>none</dns-domain-name>
        <failover-group>system-defined</failover-group>
        <failover-policy>disabled</failover-policy>
        <firewall-policy>mgmt</firewall-policy>
        <home-node>%(node)s</home-node>
        <home-port>e0c</home-port>
        <interface-name>cluster_mgmt</interface-name>
        <is-auto-revert>true</is-auto-revert>
        <is-home>true</is-home>
        <lif-uuid>d3230112-7524-11e4-8608-123478563412</lif-uuid>
        <listen-for-dns-query>false</listen-for-dns-query>
        <netmask>%(netmask)s</netmask>
        <netmask-length>24</netmask-length>
        <operational-status>up</operational-status>
        <role>cluster_mgmt</role>
        <routing-group-name>c192.168.228.0/24</routing-group-name>
        <use-failover-group>system_defined</use-failover-group>
        <vserver>cluster3</vserver>
      </net-interface-info>
      <net-interface-info>
        <address>192.168.228.43</address>
        <address-family>ipv4</address-family>
        <administrative-status>up</administrative-status>
        <current-node>%(node)s</current-node>
        <current-port>e0d</current-port>
        <dns-domain-name>none</dns-domain-name>
        <failover-group>system-defined</failover-group>
        <failover-policy>nextavail</failover-policy>
        <firewall-policy>mgmt</firewall-policy>
        <home-node>%(node)s</home-node>
        <home-port>e0d</home-port>
        <interface-name>mgmt1</interface-name>
        <is-auto-revert>true</is-auto-revert>
        <is-home>true</is-home>
        <lif-uuid>0ccc57cc-7525-11e4-8608-123478563412</lif-uuid>
        <listen-for-dns-query>false</listen-for-dns-query>
        <netmask>%(netmask)s</netmask>
        <netmask-length>24</netmask-length>
        <operational-status>up</operational-status>
        <role>node_mgmt</role>
        <routing-group-name>n192.168.228.0/24</routing-group-name>
        <use-failover-group>system_defined</use-failover-group>
        <vserver>cluster3-01</vserver>
      </net-interface-info>
      <net-interface-info>
        <address>%(address)s</address>
        <address-family>ipv4</address-family>
        <administrative-status>up</administrative-status>
        <current-node>%(node)s</current-node>
        <current-port>%(vlan)s</current-port>
        <data-protocols>
          <data-protocol>nfs</data-protocol>
          <data-protocol>cifs</data-protocol>
        </data-protocols>
        <dns-domain-name>none</dns-domain-name>
        <failover-group>system-defined</failover-group>
        <failover-policy>nextavail</failover-policy>
        <firewall-policy>data</firewall-policy>
        <home-node>%(node)s</home-node>
        <home-port>%(vlan)s</home-port>
        <interface-name>%(lif)s</interface-name>
        <is-auto-revert>false</is-auto-revert>
        <is-home>true</is-home>
        <lif-uuid>db4d91b6-95d9-11e4-8608-123478563412</lif-uuid>
        <listen-for-dns-query>false</listen-for-dns-query>
        <netmask>%(netmask)s</netmask>
        <netmask-length>24</netmask-length>
        <operational-status>up</operational-status>
        <role>data</role>
        <routing-group-name>d10.0.0.0/24</routing-group-name>
        <use-failover-group>system_defined</use-failover-group>
        <vserver>%(vserver)s</vserver>
      </net-interface-info>
    </attributes-list>
    <num-records>3</num-records>
  </results>
""" % {
    'lif': LIF_NAME,
    'vserver': VSERVER_NAME,
    'node': NODE_NAME,
    'address': IP_ADDRESS,
    'netmask': NETMASK,
    'vlan': VLAN_PORT,
})

LIF_NAMES = ('cluster_mgmt', 'mgmt1', LIF_NAME)

NET_INTERFACE_GET_ITER_RESPONSE_NFS = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-interface-info>
        <address>%(address)s</address>
        <address-family>ipv4</address-family>
        <administrative-status>up</administrative-status>
        <current-node>%(node)s</current-node>
        <current-port>%(vlan)s</current-port>
        <data-protocols>
          <data-protocol>nfs</data-protocol>
          <data-protocol>cifs</data-protocol>
        </data-protocols>
        <dns-domain-name>none</dns-domain-name>
        <failover-group>system-defined</failover-group>
        <failover-policy>nextavail</failover-policy>
        <firewall-policy>data</firewall-policy>
        <home-node>%(node)s</home-node>
        <home-port>%(vlan)s</home-port>
        <interface-name>%(lif)s</interface-name>
        <is-auto-revert>false</is-auto-revert>
        <is-home>true</is-home>
        <lif-uuid>db4d91b6-95d9-11e4-8608-123478563412</lif-uuid>
        <listen-for-dns-query>false</listen-for-dns-query>
        <netmask>%(netmask)s</netmask>
        <netmask-length>24</netmask-length>
        <operational-status>up</operational-status>
        <role>data</role>
        <routing-group-name>d10.0.0.0/24</routing-group-name>
        <use-failover-group>system_defined</use-failover-group>
        <vserver>%(vserver)s</vserver>
      </net-interface-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'lif': LIF_NAME,
    'vserver': VSERVER_NAME,
    'node': NODE_NAME,
    'address': IP_ADDRESS,
    'netmask': NETMASK,
    'vlan': VLAN_PORT,
})

LIFS = (
    {'address': '192.168.228.42',
     'home-node': NODE_NAME,
     'home-port': 'e0c',
     'interface-name': 'cluster_mgmt',
     'netmask': NETMASK,
     'role': 'cluster_mgmt',
     'vserver': 'cluster3'
     },
    {'address': '192.168.228.43',
     'home-node': NODE_NAME,
     'home-port': 'e0d',
     'interface-name': 'mgmt1',
     'netmask': NETMASK,
     'role': 'node_mgmt',
     'vserver': 'cluster3-01'
     },
    {'address': IP_ADDRESS,
     'home-node': NODE_NAME,
     'home-port': VLAN_PORT,
     'interface-name': LIF_NAME,
     'netmask': NETMASK,
     'role': 'data',
     'vserver': VSERVER_NAME,
     },
)

NFS_LIFS = [
    {'address': IP_ADDRESS,
     'home-node': NODE_NAME,
     'home-port': VLAN_PORT,
     'interface-name': LIF_NAME,
     'netmask': NETMASK,
     'role': 'data',
     'vserver': VSERVER_NAME,
     },
]

NFS_LIFS_REST = [
    {
        'uuid': 'fake_uuid_1',
        'address': IP_ADDRESS,
        'home-node': NODE_NAME,
        'home-port': VLAN_PORT,
        'interface-name': LIF_NAME,
        'netmask': NETMASK,
        'role': 'data',
        'vserver': VSERVER_NAME,
    },
    {
        'uuid': 'fake_uuid_2',
        'address': IP_ADDRESS,
        'home-node': NODE_NAME,
        'home-port': VLAN_PORT,
        'interface-name': LIF_NAME,
        'netmask': NETMASK,
        'role': 'data',
        'vserver': VSERVER_NAME,
    },
    {
        'uuid': 'fake_uuid_3',
        'address': IP_ADDRESS,
        'home-node': NODE_NAME,
        'home-port': VLAN_PORT,
        'interface-name': LIF_NAME,
        'netmask': NETMASK,
        'role': 'data',
        'vserver': VSERVER_NAME,
    },
]

NET_INTERFACE_GET_ONE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <net-interface-info>
        <interface-name>%(lif)s</interface-name>
        <vserver>%(vserver)s</vserver>
      </net-interface-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'lif': LIF_NAME, 'vserver': VSERVER_NAME})

AGGR_GET_NAMES_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-raid-attributes>
        </aggr-raid-attributes>
        <aggregate-name>%(root1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
        </aggr-raid-attributes>
        <aggregate-name>%(root2)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr2)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'root1': ROOT_AGGREGATE_NAMES[0],
    'root2': ROOT_AGGREGATE_NAMES[1],
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
})

AGGR_GET_SPACE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-raid-attributes>
          <plexes>
            <plex-attributes>
              <plex-name>/%(aggr1)s/plex0</plex-name>
              <raidgroups>
                <raidgroup-attributes>
                  <raidgroup-name>/%(aggr1)s/plex0/rg0</raidgroup-name>
                </raidgroup-attributes>
              </raidgroups>
            </plex-attributes>
          </plexes>
        </aggr-raid-attributes>
        <aggr-space-attributes>
          <size-available>45670400</size-available>
          <size-total>943718400</size-total>
          <size-used>898048000</size-used>
        </aggr-space-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
          <plexes>
            <plex-attributes>
              <plex-name>/%(aggr2)s/plex0</plex-name>
              <raidgroups>
                <raidgroup-attributes>
                  <raidgroup-name>/%(aggr2)s/plex0/rg0</raidgroup-name>
                </raidgroup-attributes>
                <raidgroup-attributes>
                  <raidgroup-name>/%(aggr2)s/plex0/rg1</raidgroup-name>
                </raidgroup-attributes>
              </raidgroups>
            </plex-attributes>
          </plexes>
        </aggr-raid-attributes>
        <aggr-space-attributes>
          <size-available>4267659264</size-available>
          <size-total>7549747200</size-total>
          <size-used>3282087936</size-used>
        </aggr-space-attributes>
        <aggregate-name>%(aggr2)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
})

AGGR_GET_NODE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-ownership-attributes>
          <home-name>%(node)s</home-name>
        </aggr-ownership-attributes>
        <aggregate-name>%(aggr)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'aggr': SHARE_AGGREGATE_NAME,
    'node': NODE_NAME
})

AGGR_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-64bit-upgrade-attributes>
          <aggr-status-attributes>
            <is-64-bit-upgrade-in-progress>false</is-64-bit-upgrade-in-progress>
          </aggr-status-attributes>
        </aggr-64bit-upgrade-attributes>
        <aggr-fs-attributes>
          <block-type>64_bit</block-type>
          <fsid>1758646411</fsid>
          <type>aggr</type>
        </aggr-fs-attributes>
        <aggr-inode-attributes>
          <files-private-used>512</files-private-used>
          <files-total>30384</files-total>
          <files-used>96</files-used>
          <inodefile-private-capacity>30384</inodefile-private-capacity>
          <inodefile-public-capacity>30384</inodefile-public-capacity>
          <maxfiles-available>30384</maxfiles-available>
          <maxfiles-possible>243191</maxfiles-possible>
          <maxfiles-used>96</maxfiles-used>
          <percent-inode-used-capacity>0</percent-inode-used-capacity>
        </aggr-inode-attributes>
        <aggr-ownership-attributes>
          <home-id>4082368507</home-id>
          <home-name>cluster3-01</home-name>
          <owner-id>4082368507</owner-id>
          <owner-name>cluster3-01</owner-name>
        </aggr-ownership-attributes>
        <aggr-performance-attributes>
          <free-space-realloc>off</free-space-realloc>
          <max-write-alloc-blocks>0</max-write-alloc-blocks>
        </aggr-performance-attributes>
        <aggr-raid-attributes>
          <checksum-status>active</checksum-status>
          <checksum-style>block</checksum-style>
          <disk-count>3</disk-count>
          <ha-policy>cfo</ha-policy>
          <has-local-root>true</has-local-root>
          <has-partner-root>false</has-partner-root>
          <is-checksum-enabled>true</is-checksum-enabled>
          <is-hybrid>false</is-hybrid>
          <is-hybrid-enabled>false</is-hybrid-enabled>
          <is-inconsistent>false</is-inconsistent>
          <mirror-status>unmirrored</mirror-status>
          <mount-state>online</mount-state>
          <plex-count>1</plex-count>
          <plexes>
            <plex-attributes>
              <is-online>true</is-online>
              <is-resyncing>false</is-resyncing>
              <plex-name>/%(aggr1)s/plex0</plex-name>
              <plex-status>normal,active</plex-status>
              <raidgroups>
                <raidgroup-attributes>
                  <checksum-style>block</checksum-style>
                  <is-cache-tier>false</is-cache-tier>
                  <is-recomputing-parity>false</is-recomputing-parity>
                  <is-reconstructing>false</is-reconstructing>
                  <raidgroup-name>/%(aggr1)s/plex0/rg0</raidgroup-name>
                  <recomputing-parity-percentage>0</recomputing-parity-percentage>
                  <reconstruction-percentage>0</reconstruction-percentage>
                </raidgroup-attributes>
              </raidgroups>
              <resyncing-percentage>0</resyncing-percentage>
            </plex-attributes>
          </plexes>
          <raid-lost-write-state>on</raid-lost-write-state>
          <raid-size>16</raid-size>
          <raid-status>raid_dp, normal</raid-status>
          <raid-type>raid_dp</raid-type>
          <state>online</state>
        </aggr-raid-attributes>
        <aggr-snaplock-attributes>
          <is-snaplock>false</is-snaplock>
        </aggr-snaplock-attributes>
        <aggr-snapshot-attributes>
          <files-total>0</files-total>
          <files-used>0</files-used>
          <is-snapshot-auto-create-enabled>true</is-snapshot-auto-create-enabled>
          <is-snapshot-auto-delete-enabled>true</is-snapshot-auto-delete-enabled>
          <maxfiles-available>0</maxfiles-available>
          <maxfiles-possible>0</maxfiles-possible>
          <maxfiles-used>0</maxfiles-used>
          <percent-inode-used-capacity>0</percent-inode-used-capacity>
          <percent-used-capacity>0</percent-used-capacity>
          <size-available>0</size-available>
          <size-total>0</size-total>
          <size-used>0</size-used>
          <snapshot-reserve-percent>0</snapshot-reserve-percent>
        </aggr-snapshot-attributes>
        <aggr-space-attributes>
          <aggregate-metadata>245760</aggregate-metadata>
          <hybrid-cache-size-total>0</hybrid-cache-size-total>
          <percent-used-capacity>95</percent-used-capacity>
          <size-available>45670400</size-available>
          <size-total>943718400</size-total>
          <size-used>898048000</size-used>
          <total-reserved-space>0</total-reserved-space>
          <used-including-snapshot-reserve>898048000</used-including-snapshot-reserve>
          <volume-footprints>897802240</volume-footprints>
        </aggr-space-attributes>
        <aggr-volume-count-attributes>
          <flexvol-count>1</flexvol-count>
          <flexvol-count-collective>0</flexvol-count-collective>
          <flexvol-count-striped>0</flexvol-count-striped>
        </aggr-volume-count-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
        <aggregate-uuid>15863632-ea49-49a8-9c88-2bd2d57c6d7a</aggregate-uuid>
        <nodes>
          <node-name>cluster3-01</node-name>
        </nodes>
        <striping-type>unknown</striping-type>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-64bit-upgrade-attributes>
          <aggr-status-attributes>
            <is-64-bit-upgrade-in-progress>false</is-64-bit-upgrade-in-progress>
          </aggr-status-attributes>
        </aggr-64bit-upgrade-attributes>
        <aggr-fs-attributes>
          <block-type>64_bit</block-type>
          <fsid>706602229</fsid>
          <type>aggr</type>
        </aggr-fs-attributes>
        <aggr-inode-attributes>
          <files-private-used>528</files-private-used>
          <files-total>31142</files-total>
          <files-used>96</files-used>
          <inodefile-private-capacity>31142</inodefile-private-capacity>
          <inodefile-public-capacity>31142</inodefile-public-capacity>
          <maxfiles-available>31142</maxfiles-available>
          <maxfiles-possible>1945584</maxfiles-possible>
          <maxfiles-used>96</maxfiles-used>
          <percent-inode-used-capacity>0</percent-inode-used-capacity>
        </aggr-inode-attributes>
        <aggr-ownership-attributes>
          <home-id>4082368507</home-id>
          <home-name>cluster3-01</home-name>
          <owner-id>4082368507</owner-id>
          <owner-name>cluster3-01</owner-name>
        </aggr-ownership-attributes>
        <aggr-performance-attributes>
          <free-space-realloc>off</free-space-realloc>
          <max-write-alloc-blocks>0</max-write-alloc-blocks>
        </aggr-performance-attributes>
        <aggr-raid-attributes>
          <checksum-status>active</checksum-status>
          <checksum-style>block</checksum-style>
          <disk-count>10</disk-count>
          <ha-policy>sfo</ha-policy>
          <has-local-root>false</has-local-root>
          <has-partner-root>false</has-partner-root>
          <is-checksum-enabled>true</is-checksum-enabled>
          <is-hybrid>false</is-hybrid>
          <is-hybrid-enabled>false</is-hybrid-enabled>
          <is-inconsistent>false</is-inconsistent>
          <mirror-status>unmirrored</mirror-status>
          <mount-state>online</mount-state>
          <plex-count>1</plex-count>
          <plexes>
            <plex-attributes>
              <is-online>true</is-online>
              <is-resyncing>false</is-resyncing>
              <plex-name>/%(aggr2)s/plex0</plex-name>
              <plex-status>normal,active</plex-status>
              <raidgroups>
                <raidgroup-attributes>
                  <checksum-style>block</checksum-style>
                  <is-cache-tier>false</is-cache-tier>
                  <is-recomputing-parity>false</is-recomputing-parity>
                  <is-reconstructing>false</is-reconstructing>
                  <raidgroup-name>/%(aggr2)s/plex0/rg0</raidgroup-name>
                  <recomputing-parity-percentage>0</recomputing-parity-percentage>
                  <reconstruction-percentage>0</reconstruction-percentage>
                </raidgroup-attributes>
                <raidgroup-attributes>
                  <checksum-style>block</checksum-style>
                  <is-cache-tier>false</is-cache-tier>
                  <is-recomputing-parity>false</is-recomputing-parity>
                  <is-reconstructing>false</is-reconstructing>
                  <raidgroup-name>/%(aggr2)s/plex0/rg1</raidgroup-name>
                  <recomputing-parity-percentage>0</recomputing-parity-percentage>
                  <reconstruction-percentage>0</reconstruction-percentage>
                </raidgroup-attributes>
              </raidgroups>
              <resyncing-percentage>0</resyncing-percentage>
            </plex-attributes>
          </plexes>
          <raid-lost-write-state>on</raid-lost-write-state>
          <raid-size>8</raid-size>
          <raid-status>raid4, normal</raid-status>
          <raid-type>raid4</raid-type>
          <state>online</state>
        </aggr-raid-attributes>
        <aggr-snaplock-attributes>
          <is-snaplock>false</is-snaplock>
        </aggr-snaplock-attributes>
        <aggr-snapshot-attributes>
          <files-total>0</files-total>
          <files-used>0</files-used>
          <is-snapshot-auto-create-enabled>true</is-snapshot-auto-create-enabled>
          <is-snapshot-auto-delete-enabled>true</is-snapshot-auto-delete-enabled>
          <maxfiles-available>0</maxfiles-available>
          <maxfiles-possible>0</maxfiles-possible>
          <maxfiles-used>0</maxfiles-used>
          <percent-inode-used-capacity>0</percent-inode-used-capacity>
          <percent-used-capacity>0</percent-used-capacity>
          <size-available>0</size-available>
          <size-total>0</size-total>
          <size-used>0</size-used>
          <snapshot-reserve-percent>0</snapshot-reserve-percent>
        </aggr-snapshot-attributes>
        <aggr-space-attributes>
          <aggregate-metadata>425984</aggregate-metadata>
          <hybrid-cache-size-total>0</hybrid-cache-size-total>
          <percent-used-capacity>15</percent-used-capacity>
          <size-available>6448431104</size-available>
          <size-total>7549747200</size-total>
          <size-used>1101316096</size-used>
          <total-reserved-space>0</total-reserved-space>
          <used-including-snapshot-reserve>1101316096</used-including-snapshot-reserve>
          <volume-footprints>1100890112</volume-footprints>
        </aggr-space-attributes>
        <aggr-volume-count-attributes>
          <flexvol-count>2</flexvol-count>
          <flexvol-count-collective>0</flexvol-count-collective>
          <flexvol-count-striped>0</flexvol-count-striped>
        </aggr-volume-count-attributes>
        <aggregate-name>%(aggr2)s</aggregate-name>
        <aggregate-uuid>2a741934-1aaf-42dd-93ca-aaf231be108a</aggregate-uuid>
        <nodes>
          <node-name>cluster3-01</node-name>
        </nodes>
        <striping-type>not_striped</striping-type>
      </aggr-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
})

AGGR_GET_ITER_SSC_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-64bit-upgrade-attributes>
          <aggr-status-attributes>
            <is-64-bit-upgrade-in-progress>false</is-64-bit-upgrade-in-progress>
          </aggr-status-attributes>
        </aggr-64bit-upgrade-attributes>
        <aggr-fs-attributes>
          <block-type>64_bit</block-type>
          <fsid>1758646411</fsid>
          <type>aggr</type>
        </aggr-fs-attributes>
        <aggr-inode-attributes>
          <files-private-used>512</files-private-used>
          <files-total>30384</files-total>
          <files-used>96</files-used>
          <inodefile-private-capacity>30384</inodefile-private-capacity>
          <inodefile-public-capacity>30384</inodefile-public-capacity>
          <maxfiles-available>30384</maxfiles-available>
          <maxfiles-possible>243191</maxfiles-possible>
          <maxfiles-used>96</maxfiles-used>
          <percent-inode-used-capacity>0</percent-inode-used-capacity>
        </aggr-inode-attributes>
        <aggr-ownership-attributes>
          <home-id>4082368507</home-id>
          <home-name>cluster3-01</home-name>
          <owner-id>4082368507</owner-id>
          <owner-name>cluster3-01</owner-name>
        </aggr-ownership-attributes>
        <aggr-performance-attributes>
          <free-space-realloc>off</free-space-realloc>
          <max-write-alloc-blocks>0</max-write-alloc-blocks>
        </aggr-performance-attributes>
        <aggr-raid-attributes>
          <checksum-status>active</checksum-status>
          <checksum-style>block</checksum-style>
          <disk-count>3</disk-count>
          <ha-policy>cfo</ha-policy>
          <has-local-root>true</has-local-root>
          <has-partner-root>false</has-partner-root>
          <is-checksum-enabled>true</is-checksum-enabled>
          <is-hybrid>false</is-hybrid>
          <is-hybrid-enabled>false</is-hybrid-enabled>
          <is-inconsistent>false</is-inconsistent>
          <mirror-status>unmirrored</mirror-status>
          <mount-state>online</mount-state>
          <plex-count>1</plex-count>
          <plexes>
            <plex-attributes>
              <is-online>true</is-online>
              <is-resyncing>false</is-resyncing>
              <plex-name>/%(aggr1)s/plex0</plex-name>
              <plex-status>normal,active</plex-status>
              <raidgroups>
                <raidgroup-attributes>
                  <checksum-style>block</checksum-style>
                  <is-cache-tier>false</is-cache-tier>
                  <is-recomputing-parity>false</is-recomputing-parity>
                  <is-reconstructing>false</is-reconstructing>
                  <raidgroup-name>/%(aggr1)s/plex0/rg0</raidgroup-name>
                  <recomputing-parity-percentage>0</recomputing-parity-percentage>
                  <reconstruction-percentage>0</reconstruction-percentage>
                </raidgroup-attributes>
              </raidgroups>
              <resyncing-percentage>0</resyncing-percentage>
            </plex-attributes>
          </plexes>
          <raid-lost-write-state>on</raid-lost-write-state>
          <raid-size>16</raid-size>
          <raid-status>raid_dp, normal</raid-status>
          <raid-type>raid_dp</raid-type>
          <state>online</state>
        </aggr-raid-attributes>
        <aggr-snaplock-attributes>
          <is-snaplock>false</is-snaplock>
        </aggr-snaplock-attributes>
        <aggr-snapshot-attributes>
          <files-total>0</files-total>
          <files-used>0</files-used>
          <is-snapshot-auto-create-enabled>true</is-snapshot-auto-create-enabled>
          <is-snapshot-auto-delete-enabled>true</is-snapshot-auto-delete-enabled>
          <maxfiles-available>0</maxfiles-available>
          <maxfiles-possible>0</maxfiles-possible>
          <maxfiles-used>0</maxfiles-used>
          <percent-inode-used-capacity>0</percent-inode-used-capacity>
          <percent-used-capacity>0</percent-used-capacity>
          <size-available>0</size-available>
          <size-total>0</size-total>
          <size-used>0</size-used>
          <snapshot-reserve-percent>0</snapshot-reserve-percent>
        </aggr-snapshot-attributes>
        <aggr-space-attributes>
          <aggregate-metadata>245760</aggregate-metadata>
          <hybrid-cache-size-total>0</hybrid-cache-size-total>
          <percent-used-capacity>95</percent-used-capacity>
          <size-available>45670400</size-available>
          <size-total>943718400</size-total>
          <size-used>898048000</size-used>
          <total-reserved-space>0</total-reserved-space>
          <used-including-snapshot-reserve>898048000</used-including-snapshot-reserve>
          <volume-footprints>897802240</volume-footprints>
        </aggr-space-attributes>
        <aggr-volume-count-attributes>
          <flexvol-count>1</flexvol-count>
          <flexvol-count-collective>0</flexvol-count-collective>
          <flexvol-count-striped>0</flexvol-count-striped>
        </aggr-volume-count-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
        <aggregate-uuid>15863632-ea49-49a8-9c88-2bd2d57c6d7a</aggregate-uuid>
        <nodes>
          <node-name>cluster3-01</node-name>
        </nodes>
        <striping-type>unknown</striping-type>
      </aggr-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'aggr1': SHARE_AGGREGATE_NAMES[0]})

AGGR_GET_ITER_ROOT_AGGR_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-raid-attributes>
          <has-local-root>true</has-local-root>
          <has-partner-root>false</has-partner-root>
        </aggr-raid-attributes>
        <aggregate-name>%(root1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
          <has-local-root>true</has-local-root>
          <has-partner-root>false</has-partner-root>
        </aggr-raid-attributes>
        <aggregate-name>%(root2)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
          <has-local-root>false</has-local-root>
          <has-partner-root>false</has-partner-root>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
          <has-local-root>false</has-local-root>
          <has-partner-root>false</has-partner-root>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr2)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>6</num-records>
  </results>
""" % {
    'root1': ROOT_AGGREGATE_NAMES[0],
    'root2': ROOT_AGGREGATE_NAMES[1],
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
})

AGGR_GET_ITER_NON_ROOT_AGGR_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-raid-attributes>
          <has-local-root>false</has-local-root>
          <has-partner-root>false</has-partner-root>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
          <has-local-root>false</has-local-root>
          <has-partner-root>false</has-partner-root>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr2)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>6</num-records>
  </results>
""" % {
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
})

VOLUME_GET_NAME_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(volume)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

VOLUME_GET_VOLUME_PATH_RESPONSE = etree.XML("""
  <results status="passed">
    <junction>/%(volume)s</junction>
  </results>
""" % {'volume': SHARE_NAME})

VOLUME_GET_VOLUME_PATH_CIFS_RESPONSE = etree.XML("""
  <results status="passed">
    <junction>\\%(volume)s</junction>
  </results>
""" % {'volume': SHARE_NAME})

VOLUME_JUNCTION_PATH = '/' + SHARE_NAME
VOLUME_JUNCTION_PATH_CIFS = '\\' + SHARE_NAME

VOLUME_MODIFY_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <failure-list />
    <num-failed>0</num-failed>
    <num-succeeded>1</num-succeeded>
    <success-list>
      <volume-modify-iter-info>
        <volume-key>
          <volume-attributes>
            <volume-id-attributes>
              <name>%(volume)s</name>
              <owning-vserver-name>%(vserver)s</owning-vserver-name>
            </volume-id-attributes>
          </volume-attributes>
        </volume-key>
      </volume-modify-iter-info>
    </success-list>
  </results>
""" % {'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

VOLUME_MODIFY_ITER_ERROR_RESPONSE = etree.XML("""
  <results status="passed">
    <failure-list>
      <volume-modify-iter-info>
        <error-code>160</error-code>
        <error-message>Unable to set volume attribute "size"</error-message>
        <volume-key>
          <volume-attributes>
            <volume-id-attributes>
              <name>%(volume)s</name>
              <owning-vserver-name>%(vserver)s</owning-vserver-name>
            </volume-id-attributes>
          </volume-attributes>
        </volume-key>
      </volume-modify-iter-info>
    </failure-list>
    <num-failed>1</num-failed>
    <num-succeeded>0</num-succeeded>
  </results>
""" % {'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

SNAPSHOT_ACCESS_TIME = '1466640058'
SNAPSHOT_GET_ITER_NOT_BUSY_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
        <access-time>%(access_time)s</access-time>
        <busy>false</busy>
        <name>%(snap)s</name>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </snapshot-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'access_time': SNAPSHOT_ACCESS_TIME,
    'snap': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'vserver': VSERVER_NAME,
})

SNAPSHOT_GET_ITER_BUSY_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
        <access-time>%(access_time)s</access-time>
        <busy>true</busy>
        <name>%(snap)s</name>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
        <snapshot-owners-list>
          <snapshot-owner>
            <owner>volume clone</owner>
          </snapshot-owner>
        </snapshot-owners-list>
      </snapshot-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'access_time': SNAPSHOT_ACCESS_TIME,
    'snap': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'vserver': VSERVER_NAME,
})

SNAPSHOT_GET_ITER_NOT_UNIQUE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
        <busy>false</busy>
        <name>%(snap)s</name>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </snapshot-info>
      <snapshot-info>
        <busy>false</busy>
        <name>%(snap)s</name>
        <volume>%(root_volume)s</volume>
        <vserver>%(admin_vserver)s</vserver>
      </snapshot-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'snap': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'vserver': VSERVER_NAME,
    'root_volume': ROOT_VOLUME_NAME,
    'admin_vserver': ADMIN_VSERVER_NAME,
})

SNAPSHOT_GET_ITER_UNAVAILABLE_RESPONSE = etree.XML("""
  <results status="passed">
    <num-records>0</num-records>
    <volume-errors>
      <volume-error>
        <errno>13023</errno>
        <name>%(volume)s</name>
        <reason>Unable to get information for Snapshot copies of volume \
"%(volume)s" on Vserver "%(vserver)s". Reason: Volume not online.</reason>
        <vserver>%(vserver)s</vserver>
      </volume-error>
    </volume-errors>
  </results>
""" % {'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

SNAPSHOT_GET_ITER_OTHER_ERROR_RESPONSE = etree.XML("""
  <results status="passed">
    <num-records>0</num-records>
    <volume-errors>
      <volume-error>
        <errno>99999</errno>
        <name>%(volume)s</name>
        <reason>Unable to get information for Snapshot copies of volume \
"%(volume)s" on Vserver "%(vserver)s".</reason>
        <vserver>%(vserver)s</vserver>
      </volume-error>
    </volume-errors>
  </results>
""" % {'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

SNAPSHOT_MULTIDELETE_ERROR_RESPONSE = etree.XML("""
  <results status="passed">
    <volume-errors>
      <volume-error>
        <errno>13021</errno>
        <name>%(volume)s</name>
        <reason>No such snapshot.</reason>
      </volume-error>
    </volume-errors>
  </results>
""" % {'volume': SHARE_NAME})

SNAPSHOT_GET_ITER_DELETED_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
        <name>deleted_manila_%(snap)s</name>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </snapshot-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'snap': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'vserver': VSERVER_NAME,
})

SNAPSHOT_GET_ITER_SNAPMIRROR_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
        <name>%(snap)s</name>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </snapshot-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>

""" % {
    'snap': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'vserver': VSERVER_NAME,
})

CIFS_SHARE_ACCESS_CONTROL_GET_ITER = etree.XML("""
  <results status="passed">
    <attributes-list>
      <cifs-share-access-control>
        <permission>full_control</permission>
        <share>%(volume)s</share>
        <user-or-group>Administrator</user-or-group>
        <vserver>manila_svm_cifs</vserver>
      </cifs-share-access-control>
      <cifs-share-access-control>
        <permission>change</permission>
        <share>%(volume)s</share>
        <user-or-group>Administrators</user-or-group>
        <vserver>manila_svm_cifs</vserver>
      </cifs-share-access-control>
      <cifs-share-access-control>
        <permission>read</permission>
        <share>%(volume)s</share>
        <user-or-group>Power Users</user-or-group>
        <vserver>manila_svm_cifs</vserver>
      </cifs-share-access-control>
      <cifs-share-access-control>
        <permission>no_access</permission>
        <share>%(volume)s</share>
        <user-or-group>Users</user-or-group>
        <vserver>manila_svm_cifs</vserver>
      </cifs-share-access-control>
    </attributes-list>
    <num-records>4</num-records>
  </results>
""" % {'volume': SHARE_NAME})

CIFS_SHARE_GET_ITER_RESPONSE = etree.XML("""
 <results status="passed">
    <attributes-list>
      <cifs-share>
        <share-name>%(share_name)s</share-name>
        <vserver>fake_vserver</vserver>
      </cifs-share>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'share_name': SHARE_NAME})

NFS_EXPORT_RULES = ('10.10.10.10', '10.10.10.20')

NFS_EXPORTFS_LIST_RULES_2_NO_RULES_RESPONSE = etree.XML("""
  <results status="passed">
    <rules />
  </results>
""")

NFS_EXPORTFS_LIST_RULES_2_RESPONSE = etree.XML("""
  <results status="passed">
    <rules>
      <exports-rule-info-2>
        <pathname>%(path)s</pathname>
        <security-rules>
          <security-rule-info>
            <anon>65534</anon>
            <nosuid>false</nosuid>
            <read-only>
              <exports-hostname-info>
                <name>%(host1)s</name>
              </exports-hostname-info>
              <exports-hostname-info>
                <name>%(host2)s</name>
              </exports-hostname-info>
            </read-only>
            <read-write>
              <exports-hostname-info>
                <name>%(host1)s</name>
              </exports-hostname-info>
              <exports-hostname-info>
                <name>%(host2)s</name>
              </exports-hostname-info>
            </read-write>
            <root>
              <exports-hostname-info>
                <name>%(host1)s</name>
              </exports-hostname-info>
              <exports-hostname-info>
                <name>%(host2)s</name>
              </exports-hostname-info>
            </root>
            <sec-flavor>
              <sec-flavor-info>
                <flavor>sys</flavor>
              </sec-flavor-info>
            </sec-flavor>
          </security-rule-info>
        </security-rules>
      </exports-rule-info-2>
    </rules>
  </results>
""" % {
    'path': VOLUME_JUNCTION_PATH,
    'host1': NFS_EXPORT_RULES[0],
    'host2': NFS_EXPORT_RULES[1],
})

AGGR_GET_RAID_TYPE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <aggr-attributes>
        <aggr-raid-attributes>
          <plexes>
            <plex-attributes>
              <plex-name>/%(aggr1)s/plex0</plex-name>
              <raidgroups>
                <raidgroup-attributes>
                  <raidgroup-name>/%(aggr1)s/plex0/rg0</raidgroup-name>
                </raidgroup-attributes>
              </raidgroups>
            </plex-attributes>
          </plexes>
          <raid-type>%(raid_type1)s</raid-type>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr1)s</aggregate-name>
      </aggr-attributes>
      <aggr-attributes>
        <aggr-raid-attributes>
          <plexes>
            <plex-attributes>
              <plex-name>/%(aggr2)s/plex0</plex-name>
              <raidgroups>
                <raidgroup-attributes>
                  <raidgroup-name>/%(aggr2)s/plex0/rg0</raidgroup-name>
                </raidgroup-attributes>
                <raidgroup-attributes>
                  <raidgroup-name>/%(aggr2)s/plex0/rg1</raidgroup-name>
                </raidgroup-attributes>
              </raidgroups>
            </plex-attributes>
          </plexes>
          <raid-type>%(raid_type2)s</raid-type>
        </aggr-raid-attributes>
        <aggregate-name>%(aggr2)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'aggr1': SHARE_AGGREGATE_NAMES[0],
    'aggr2': SHARE_AGGREGATE_NAMES[1],
    'raid_type1': SHARE_AGGREGATE_RAID_TYPES[0],
    'raid_type2': SHARE_AGGREGATE_RAID_TYPES[1]
})

STORAGE_DISK_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.19</disk-name>
        <disk-raid-info>
          <effective-disk-type>%(type0)s</effective-disk-type>
        </disk-raid-info>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.20</disk-name>
        <disk-raid-info>
          <effective-disk-type>%(type0)s</effective-disk-type>
        </disk-raid-info>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.20</disk-name>
        <disk-raid-info>
          <effective-disk-type>%(type1)s</effective-disk-type>
        </disk-raid-info>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.20</disk-name>
        <disk-raid-info>
          <effective-disk-type>%(type1)s</effective-disk-type>
        </disk-raid-info>
      </storage-disk-info>
    </attributes-list>
    <num-records>4</num-records>
  </results>
""" % {
    'type0': SHARE_AGGREGATE_DISK_TYPES[0],
    'type1': SHARE_AGGREGATE_DISK_TYPES[1],
})

STORAGE_DISK_GET_ITER_RESPONSE_PAGE_1 = etree.XML("""
  <results status="passed">
    <attributes-list>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.16</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.17</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.18</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.19</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.20</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.21</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.22</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.24</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.25</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.26</disk-name>
      </storage-disk-info>
    </attributes-list>
    <next-tag>next_tag_1</next-tag>
    <num-records>10</num-records>
  </results>
""")

STORAGE_DISK_GET_ITER_RESPONSE_PAGE_2 = etree.XML("""
  <results status="passed">
    <attributes-list>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.27</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.28</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.29</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v4.32</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.16</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.17</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.18</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.19</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.20</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.21</disk-name>
      </storage-disk-info>
    </attributes-list>
    <next-tag>next_tag_2</next-tag>
    <num-records>10</num-records>
  </results>
""")

STORAGE_DISK_GET_ITER_RESPONSE_PAGE_3 = etree.XML("""
  <results status="passed">
    <attributes-list>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.22</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.24</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.25</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.26</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.27</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.28</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.29</disk-name>
      </storage-disk-info>
      <storage-disk-info>
        <disk-name>cluster3-01:v5.32</disk-name>
      </storage-disk-info>
    </attributes-list>
    <num-records>8</num-records>
  </results>
""")

GET_AGGREGATE_FOR_VOLUME_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <containing-aggregate-name>%(aggr)s</containing-aggregate-name>
          <name>%(share)s</name>
          <owning-vserver-name>os_aa666789-5576-4835-87b7-868069856459</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'aggr': SHARE_AGGREGATE_NAME,
    'share': SHARE_NAME
})

GET_AGGREGATE_FOR_FLEXGROUP_VOL_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <aggr-list>
            <aggr-name>%(aggr)s</aggr-name>
          </aggr-list>
          <name>%(share)s</name>
          <owning-vserver-name>os_aa666789-5576-4835-87b7-868069856459</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'aggr': SHARE_AGGREGATE_NAME,
    'share': SHARE_NAME
})

VOLUME_AUTOSIZE_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <grow-threshold-percent>%(grow_percent)s</grow-threshold-percent>
    <is-enabled>false</is-enabled>
    <maximum-size>%(max_size)s</maximum-size>
    <minimum-size>%(min_size)s</minimum-size>
    <mode>%(mode)s</mode>
    <shrink-threshold-percent>%(shrink_percent)s</shrink-threshold-percent>
  </results>
""" % {'grow_percent': VOLUME_AUTOSIZE_ATTRS.get('grow-threshold-percent'),
       'max_size': VOLUME_AUTOSIZE_ATTRS.get('maximum-size'),
       'min_size': VOLUME_AUTOSIZE_ATTRS.get('minimum-size'),
       'mode': VOLUME_AUTOSIZE_ATTRS.get('mode'),
       'shrink_percent': VOLUME_AUTOSIZE_ATTRS.get(
           'shrink-threshold-percent')})

GET_VOLUME_FOR_ENCRYPTED_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <encrypt>true</encrypt>
        <volume-id-attributes>
          <name>%(volume)s</name>
          <owning-vserver-name>manila_svm</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'volume': SHARE_NAME})

GET_VOLUME_FOR_ENCRYPTED_OLD_SYS_VERSION_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(volume)s</name>
          <owning-vserver-name>manila_svm</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'volume': SHARE_NAME})

EXPORT_RULE_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <export-rule-info>
        <client-match>%(rule)s</client-match>
        <policy-name>%(policy)s</policy-name>
        <rule-index>3</rule-index>
        <vserver-name>manila_svm</vserver-name>
      </export-rule-info>
      <export-rule-info>
        <client-match>%(rule)s</client-match>
        <policy-name>%(policy)s</policy-name>
        <rule-index>1</rule-index>
        <vserver-name>manila_svm</vserver-name>
      </export-rule-info>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {'policy': EXPORT_POLICY_NAME, 'rule': IP_ADDRESS})

VOLUME_GET_EXPORT_POLICY_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-export-attributes>
          <policy>%(policy)s</policy>
        </volume-export-attributes>
        <volume-id-attributes>
          <name>%(volume)s</name>
          <owning-vserver-name>manila_svm</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'policy': EXPORT_POLICY_NAME, 'volume': SHARE_NAME})

DELETED_EXPORT_POLICY_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <export-policy-info>
        <policy-name>%(policy1)s</policy-name>
        <vserver>%(vserver)s</vserver>
      </export-policy-info>
      <export-policy-info>
        <policy-name>%(policy2)s</policy-name>
        <vserver>%(vserver)s</vserver>
      </export-policy-info>
      <export-policy-info>
        <policy-name>%(policy3)s</policy-name>
        <vserver>%(vserver2)s</vserver>
      </export-policy-info>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'vserver': VSERVER_NAME,
    'vserver2': VSERVER_NAME_2,
    'policy1': DELETED_EXPORT_POLICIES[VSERVER_NAME][0],
    'policy2': DELETED_EXPORT_POLICIES[VSERVER_NAME][1],
    'policy3': DELETED_EXPORT_POLICIES[VSERVER_NAME_2][0],
})

LUN_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <lun-info>
        <path>/vol/%(volume)s/fakelun</path>
        <qtree />
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </lun-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'vserver': VSERVER_NAME,
    'volume': SHARE_NAME,
})

VOLUME_GET_ITER_NOT_UNIQUE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(volume1)s</name>
        </volume-id-attributes>
      </volume-attributes>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(volume2)s</name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'volume1': SHARE_NAME,
    'volume2': SHARE_NAME_2,
})

VOLUME_GET_ITER_JUNCTIONED_VOLUMES_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>fake_volume</name>
          <owning-vserver-name>test</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""")

VOLUME_GET_ITER_VOLUME_TO_MANAGE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <containing-aggregate-name>%(aggr)s</containing-aggregate-name>
          <junction-path>/%(volume)s</junction-path>
          <name>%(volume)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
          <style>flex</style>
          <type>rw</type>
          <style-extended>%(style-extended)s</style-extended>
        </volume-id-attributes>
        <volume-space-attributes>
          <size>%(size)s</size>
        </volume-space-attributes>
        <volume-qos-attributes>
          <policy-group-name>%(qos-policy-group-name)s</policy-group-name>
        </volume-qos-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'aggr': SHARE_AGGREGATE_NAME,
    'vserver': VSERVER_NAME,
    'volume': SHARE_NAME,
    'size': SHARE_SIZE,
    'qos-policy-group-name': QOS_POLICY_GROUP_NAME,
    'style-extended': FLEXVOL_STYLE_EXTENDED,
})

VOLUME_GET_ITER_FLEXGROUP_VOLUME_TO_MANAGE_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <aggr-list>
            <aggr-name>%(aggr)s</aggr-name>
          </aggr-list>
          <junction-path>/%(volume)s</junction-path>
          <name>%(volume)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
          <style>flex</style>
          <type>rw</type>
          <style-extended>%(style-extended)s</style-extended>
        </volume-id-attributes>
        <volume-space-attributes>
          <size>%(size)s</size>
        </volume-space-attributes>
        <volume-qos-attributes>
          <policy-group-name>%(qos-policy-group-name)s</policy-group-name>
        </volume-qos-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'aggr': SHARE_AGGREGATE_NAME,
    'vserver': VSERVER_NAME,
    'volume': SHARE_NAME,
    'size': SHARE_SIZE,
    'qos-policy-group-name': QOS_POLICY_GROUP_NAME,
    'style-extended': FLEXGROUP_STYLE_EXTENDED,
})

VOLUME_GET_ITER_NO_QOS_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <containing-aggregate-name>%(aggr)s</containing-aggregate-name>
          <junction-path>/%(volume)s</junction-path>
          <name>%(volume)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
          <style>flex</style>
          <type>rw</type>
          <style-extended>%(style-extended)s</style-extended>
        </volume-id-attributes>
        <volume-space-attributes>
          <size>%(size)s</size>
        </volume-space-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'aggr': SHARE_AGGREGATE_NAME,
    'vserver': VSERVER_NAME,
    'volume': SHARE_NAME,
    'size': SHARE_SIZE,
    'style-extended': FLEXVOL_STYLE_EXTENDED,
})

CLONE_CHILD_1 = 'fake_child_1'
CLONE_CHILD_2 = 'fake_child_2'
VOLUME_GET_ITER_CLONE_CHILDREN_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(clone1)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(clone2)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'vserver': VSERVER_NAME,
    'clone1': CLONE_CHILD_1,
    'clone2': CLONE_CHILD_2,
})

VOLUME_GET_ITER_PARENT_SNAP_EMPTY_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-id-attributes>
          <name>%(name)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'vserver': VSERVER_NAME,
    'name': SHARE_NAME,
})

VOLUME_GET_ITER_PARENT_SNAP_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-attributes>
        <volume-clone-attributes>
          <volume-clone-parent-attributes>
            <snapshot-name>%(snapshot_name)s</snapshot-name>
          </volume-clone-parent-attributes>
        </volume-clone-attributes>
        <volume-id-attributes>
          <name>%(name)s</name>
          <owning-vserver-name>%(vserver)s</owning-vserver-name>
        </volume-id-attributes>
      </volume-attributes>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'snapshot_name': SNAPSHOT_NAME,
    'vserver': VSERVER_NAME,
    'name': SHARE_NAME,
})

SIS_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <sis-status-info>
        <is-compression-enabled>true</is-compression-enabled>
        <path>/vol/%(volume)s</path>
        <state>enabled</state>
        <vserver>%(vserver)s</vserver>
      </sis-status-info>
    </attributes-list>
  </results>
""" % {
    'vserver': VSERVER_NAME,
    'volume': SHARE_NAME,
})

CLUSTER_PEER_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <cluster-peer-info>
        <active-addresses>
          <remote-inet-address>%(addr1)s</remote-inet-address>
          <remote-inet-address>%(addr2)s</remote-inet-address>
        </active-addresses>
        <availability>available</availability>
        <cluster-name>%(cluster)s</cluster-name>
        <cluster-uuid>fake_uuid</cluster-uuid>
        <peer-addresses>
          <remote-inet-address>%(addr1)s</remote-inet-address>
        </peer-addresses>
        <remote-cluster-name>%(remote_cluster)s</remote-cluster-name>
        <serial-number>fake_serial_number</serial-number>
        <timeout>60</timeout>
      </cluster-peer-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'addr1': CLUSTER_ADDRESS_1,
    'addr2': CLUSTER_ADDRESS_2,
    'cluster': CLUSTER_NAME,
    'remote_cluster': REMOTE_CLUSTER_NAME,
})

CLUSTER_PEER_POLICY_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes>
      <cluster-peer-policy>
        <is-unauthenticated-access-permitted>false</is-unauthenticated-access-permitted>
        <passphrase-minimum-length>8</passphrase-minimum-length>
      </cluster-peer-policy>
    </attributes>
  </results>
""")

CLUSTER_GET_CLUSTER_NAME = etree.XML("""
  <results status="passed">
    <attributes>
      <cluster-identity-info>
        <cluster-contact />
        <cluster-location>-</cluster-location>
        <cluster-name>%(cluster_name)s</cluster-name>
        <cluster-serial-number>1-80-000000</cluster-serial-number>
        <cluster-uuid>fake_uuid</cluster-uuid>
        <rdb-uuid>fake_rdb</rdb-uuid>
      </cluster-identity-info>
    </attributes>
  </results>
""" % {
    'cluster_name': CLUSTER_NAME,
})

VSERVER_PEER_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <vserver-peer-info>
        <applications>
          <vserver-peer-application>snapmirror</vserver-peer-application>
        </applications>
        <peer-cluster>%(cluster)s</peer-cluster>
        <peer-state>peered</peer-state>
        <peer-vserver>%(vserver2)s</peer-vserver>
        <vserver>%(vserver1)s</vserver>
      </vserver-peer-info>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
    'cluster': CLUSTER_NAME,
    'vserver1': VSERVER_NAME,
    'vserver2': VSERVER_NAME_2
})

SNAPMIRROR_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapmirror-info>
        <destination-volume>fake_destination_volume</destination-volume>
        <destination-volume-node>fake_destination_node</destination-volume-node>
        <destination-vserver>fake_destination_vserver</destination-vserver>
        <exported-snapshot>fake_snapshot</exported-snapshot>
        <exported-snapshot-timestamp>1442701782</exported-snapshot-timestamp>
        <is-constituent>false</is-constituent>
        <is-healthy>true</is-healthy>
        <lag-time>2187</lag-time>
        <last-transfer-duration>109</last-transfer-duration>
        <last-transfer-end-timestamp>1442701890</last-transfer-end-timestamp>
        <last-transfer-from>test:manila</last-transfer-from>
        <last-transfer-size>1171456</last-transfer-size>
        <last-transfer-type>initialize</last-transfer-type>
        <max-transfer-rate>0</max-transfer-rate>
        <mirror-state>snapmirrored</mirror-state>
        <newest-snapshot>fake_snapshot</newest-snapshot>
        <newest-snapshot-timestamp>1442701782</newest-snapshot-timestamp>
        <policy>DPDefault</policy>
        <relationship-control-plane>v2</relationship-control-plane>
        <relationship-id>ea8bfcc6-5f1d-11e5-8446-123478563412</relationship-id>
        <relationship-status>idle</relationship-status>
        <relationship-type>data_protection</relationship-type>
        <schedule>daily</schedule>
        <source-volume>fake_source_volume</source-volume>
        <source-vserver>fake_source_vserver</source-vserver>
        <vserver>fake_destination_vserver</vserver>
      </snapmirror-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""")

SNAPMIRROR_GET_ITER_FILTERED_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapmirror-info>
        <destination-vserver>fake_destination_vserver</destination-vserver>
        <destination-volume>fake_destination_volume</destination-volume>
        <is-healthy>true</is-healthy>
        <mirror-state>snapmirrored</mirror-state>
        <relationship-status>idle</relationship-status>
        <schedule>daily</schedule>
        <source-vserver>fake_source_vserver</source-vserver>
        <source-volume>fake_source_volume</source-volume>
      </snapmirror-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""")

SNAPMIRROR_GET_ITER_FILTERED_RESPONSE_2 = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapmirror-info>
        <source-vserver>fake_source_vserver</source-vserver>
        <destination-vserver>fake_destination_vserver</destination-vserver>
        <mirror-state>snapmirrored</mirror-state>
        <relationship-status>idle</relationship-status>
      </snapmirror-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""")

SNAPMIRROR_GET_DESTINATIONS_ITER_FILTERED_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapmirror-destination-info>
        <destination-location>fake_destination_vserver:</destination-location>
        <destination-vserver>fake_destination_vserver</destination-vserver>
        <relationship-id>fake_relationship_id</relationship-id>
        <source-location>fake_source_vserver:</source-location>
        <source-vserver>fake_source_vserver</source-vserver>
      </snapmirror-destination-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""")

SNAPMIRROR_INITIALIZE_RESULT = etree.XML("""
  <results status="passed">
    <result-status>succeeded</result-status>
  </results>
""")

VOLUME_MOVE_GET_ITER_RESULT = etree.XML("""
  <results status="passed">
    <attributes-list>
      <volume-move-info>
        <cutover-action>retry_on_failure</cutover-action>
        <details>Cutover Completed::Volume move job finishing move</details>
        <estimated-completion-time>1481919246</estimated-completion-time>
        <percent-complete>82</percent-complete>
        <phase>finishing</phase>
        <state>healthy</state>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </volume-move-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {
    'volume': SHARE_NAME,
    'vserver': VSERVER_NAME,
})

NFS_INFO_STR = """
    <nfs-info>
        <is-rquota-enabled>false</is-rquota-enabled>
        <is-tcp-enabled>true</is-tcp-enabled>
        <is-v3-hide-snapshot>false</is-v3-hide-snapshot>
        <ntfs-unix-security-ops>use_export_policy</ntfs-unix-security-ops>
        <permitted-enc-types>
        <string>des</string>
        <string>des3</string>
        <string>aes_128</string>
        <string>aes_256</string>
        </permitted-enc-types>
        <tcp-max-xfer-size>65536</tcp-max-xfer-size>
        <udp-max-xfer-size>32768</udp-max-xfer-size>
        <v3-search-unconverted-filename>false</v3-search-unconverted-filename>
        <v4-inherited-acl-preserve>false</v4-inherited-acl-preserve>
    </nfs-info>
"""

NFS_INFO_DEFAULT_TREE = etree.XML(NFS_INFO_STR)

NFS_CONFIG_DEFAULT_RESULT = etree.XML("""
    <results status="passed">
       <defaults>
          %s
        </defaults>
    </results>
""" % NFS_INFO_STR)

NFS_CONFIG_SERVER_RESULT = etree.XML("""
    <results status="passed">
       <attributes-list>
        %s
       </attributes-list>
    </results>
""" % NFS_INFO_STR)

PERF_OBJECT_COUNTER_TOTAL_CP_MSECS_LABELS = [
    'SETUP', 'PRE_P0', 'P0_SNAP_DEL', 'P1_CLEAN', 'P1_QUOTA', 'IPU_DISK_ADD',
    'P2V_INOFILE', 'P2V_INO_PUB', 'P2V_INO_PRI', 'P2V_FSINFO', 'P2V_DLOG1',
    'P2V_DLOG2', 'P2V_REFCOUNT', 'P2V_TOPAA', 'P2V_DF_SCORES_SUB', 'P2V_BM',
    'P2V_SNAP', 'P2V_DF_SCORES', 'P2V_VOLINFO', 'P2V_CONT', 'P2A_INOFILE',
    'P2A_INO', 'P2A_DLOG1', 'P2A_HYA', 'P2A_DLOG2', 'P2A_FSINFO',
    'P2A_IPU_BITMAP_GROW', 'P2A_REFCOUNT', 'P2A_TOPAA', 'P2A_HYABC', 'P2A_BM',
    'P2A_SNAP', 'P2A_VOLINFO', 'P2_FLUSH', 'P2_FINISH', 'P3_WAIT',
    'P3V_VOLINFO', 'P3A_VOLINFO', 'P3_FINISH', 'P4_FINISH', 'P5_FINISH',
]

PERF_OBJECT_COUNTER_LIST_INFO_WAFL_RESPONSE = etree.XML("""
  <results status="passed">
    <counters>
      <counter-info>
        <desc>No. of times 8.3 names are accessed per second.</desc>
        <name>access_8_3_names</name>
        <privilege-level>diag</privilege-level>
        <properties>rate</properties>
        <unit>per_sec</unit>
      </counter-info>
      <counter-info>
        <desc>Array of counts of different types of CPs</desc>
        <labels>
          <label-info>wafl_timer generated CP</label-info>
          <label-info>snapshot generated CP</label-info>
          <label-info>wafl_avail_bufs generated CP</label-info>
          <label-info>dirty_blk_cnt generated CP</label-info>
          <label-info>full NV-log generated CP,back-to-back CP</label-info>
          <label-info>flush generated CP,sync generated CP</label-info>
          <label-info>deferred back-to-back CP</label-info>
          <label-info>low mbufs generated CP</label-info>
          <label-info>low datavecs generated CP</label-info>
          <label-info>nvlog replay takeover time limit CP</label-info>
        </labels>
        <name>cp_count</name>
        <privilege-level>diag</privilege-level>
        <properties>delta</properties>
        <type>array</type>
        <unit>none</unit>
      </counter-info>
      <counter-info>
        <base-counter>total_cp_msecs</base-counter>
        <desc>Array of percentage time spent in different phases of CP</desc>
        <labels>
          <label-info>%(labels)s</label-info>
        </labels>
        <name>cp_phase_times</name>
        <privilege-level>diag</privilege-level>
        <properties>percent</properties>
        <type>array</type>
        <unit>percent</unit>
      </counter-info>
    </counters>
  </results>
""" % {'labels': ','.join(PERF_OBJECT_COUNTER_TOTAL_CP_MSECS_LABELS)})

PERF_OBJECT_GET_INSTANCES_SYSTEM_RESPONSE_CMODE = etree.XML("""
  <results status="passed">
    <instances>
      <instance-data>
        <counters>
          <counter-data>
            <name>avg_processor_busy</name>
            <value>5674745133134</value>
          </counter-data>
        </counters>
        <name>system</name>
        <uuid>%(node1)s:kernel:system</uuid>
      </instance-data>
      <instance-data>
        <counters>
          <counter-data>
            <name>avg_processor_busy</name>
            <value>4077649009234</value>
          </counter-data>
        </counters>
        <name>system</name>
        <uuid>%(node2)s:kernel:system</uuid>
      </instance-data>
    </instances>
    <timestamp>1453412013</timestamp>
  </results>
""" % {'node1': NODE_NAMES[0], 'node2': NODE_NAMES[1]})

PERF_OBJECT_GET_INSTANCES_SYSTEM_RESPONSE_7MODE = etree.XML("""
  <results status="passed">
    <timestamp>1454146292</timestamp>
    <instances>
      <instance-data>
        <name>system</name>
        <counters>
          <counter-data>
            <name>avg_processor_busy</name>
            <value>13215732322</value>
          </counter-data>
        </counters>
      </instance-data>
    </instances>
  </results>""")

PERF_OBJECT_INSTANCE_LIST_INFO_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <instance-info>
        <name>system</name>
        <uuid>%(node)s:kernel:system</uuid>
      </instance-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'node': NODE_NAME})

PERF_OBJECT_INSTANCE_LIST_INFO_RESPONSE = etree.XML("""
  <results status="passed">
    <instances>
      <instance-info>
        <name>processor0</name>
      </instance-info>
      <instance-info>
        <name>processor1</name>
      </instance-info>
    </instances>
  </results>""")

NET_ROUTES_CREATE_RESPONSE = etree.XML("""
  <results status="passed">
    <result>
      <net-vs-routes-info>
        <address-family>ipv4</address-family>
        <destination>%(subnet)s</destination>
        <gateway>%(gateway)s</gateway>
        <metric>20</metric>
        <vserver>%(vserver)s</vserver>
      </net-vs-routes-info>
    </result>
  </results>""" % {
    'gateway': GATEWAY,
    'vserver': VSERVER_NAME,
    'subnet': SUBNET,
})

QOS_POLICY_GROUP_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <qos-policy-group-info>
        <max-throughput>%(max_throughput)s</max-throughput>
        <num-workloads>1</num-workloads>
        <policy-group>%(qos_policy_group_name)s</policy-group>
        <vserver>%(vserver)s</vserver>
      </qos-policy-group-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>""" % {
    'qos_policy_group_name': QOS_POLICY_GROUP_NAME,
    'vserver': VSERVER_NAME,
    'max_throughput': QOS_MAX_THROUGHPUT,
})

SNAPMIRROR_POLICY_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapmirror-policy-info>
        <policy-name>%(policy_name)s</policy-name>
        <type>%(policy_type)s</type>
        <vserver-name>%(vserver_name)s</vserver-name>
      </snapmirror-policy-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>""" % {
    'policy_name': SNAPMIRROR_POLICY_NAME,
    'policy_type': SNAPMIRROR_POLICY_TYPE,
    'vserver_name': VSERVER_NAME,
})

KERBEROS_CONFIG_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes>
      <kerberos-config-info>
        <interface-name>%(lif_name)s</interface-name>
        <is-kerberos-enabled>true</is-kerberos-enabled>
        <vserver>%(vserver_name)s</vserver>
      </kerberos-config-info>
    </attributes>
  </results>""" % {
    'lif_name': LIF_NAME,
    'vserver_name': VSERVER_NAME,
})

DNS_CONFIG_GET_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes>
      <net-dns-info>
        <attempts>1</attempts>
        <dns-state>enabled</dns-state>
        <domains>
          <string>fake_domain.com</string>
        </domains>
        <is-tld-query-enabled>true</is-tld-query-enabled>
        <name-servers>
          <ip-address>fake_dns_1</ip-address>
          <ip-address>fake_dns_2</ip-address>
        </name-servers>
        <require-packet-query-match>true</require-packet-query-match>
        <require-source-address-match>true</require-source-address-match>
        <timeout>2</timeout>
        <vserver-name>%(vserver_name)s</vserver-name>
      </net-dns-info>
    </attributes>
  </results>""" % {
    'vserver_name': VSERVER_NAME,
})

FPOLICY_EVENT_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <fpolicy-event-options-config>
        <event-name>%(event_name)s</event-name>
        <file-operations>
          <fpolicy-operation>create</fpolicy-operation>
          <fpolicy-operation>write</fpolicy-operation>
          <fpolicy-operation>rename</fpolicy-operation>
        </file-operations>
        <protocol>%(protocol)s</protocol>
        <volume-operation>false</volume-operation>
        <vserver>%(vserver_name)s</vserver>
      </fpolicy-event-options-config>
    </attributes-list>
    <num-records>1</num-records>
  </results>""" % {
    'event_name': FPOLICY_EVENT_NAME,
    'protocol': FPOLICY_PROTOCOL,
    'vserver_name': VSERVER_NAME,
})

FPOLICY_POLICY_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <fpolicy-policy-info>
        <allow-privileged-access>false</allow-privileged-access>
        <engine-name>%(engine)s</engine-name>
        <events>
          <event-name>%(event_name)s</event-name>
        </events>
        <is-mandatory>true</is-mandatory>
        <is-passthrough-read-enabled>false</is-passthrough-read-enabled>
        <policy-name>%(policy_name)s</policy-name>
        <vserver>%(vserver_name)s</vserver>
      </fpolicy-policy-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>""" % {
    'engine': FPOLICY_ENGINE,
    'event_name': FPOLICY_EVENT_NAME,
    'policy_name': FPOLICY_POLICY_NAME,
    'vserver_name': VSERVER_NAME,
})

FPOLICY_SCOPE_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <fpolicy-scope-config>
        <check-extensions-on-directories>true</check-extensions-on-directories>
        <file-extensions-to-exclude>
          <string>jpg</string>
          <string>mp3</string>
        </file-extensions-to-exclude>
        <file-extensions-to-include>
          <string>avi</string>
        </file-extensions-to-include>
        <is-monitoring-of-objects-with-no-extension-enabled>false</is-monitoring-of-objects-with-no-extension-enabled>
        <policy-name>%(policy_name)s</policy-name>
        <shares-to-include>
          <string>%(share_name)s</string>
        </shares-to-include>
        <vserver>%(vserver_name)s</vserver>
      </fpolicy-scope-config>
    </attributes-list>
    <num-records>1</num-records>
  </results>""" % {
    'policy_name': FPOLICY_POLICY_NAME,
    'share_name': SHARE_NAME,
    'vserver_name': VSERVER_NAME,
})

FPOLICY_POLICY_STATUS_GET_ITER_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <fpolicy-policy-status-info>
        <policy-name>%(policy_name)s</policy-name>
        <sequence-number>1</sequence-number>
        <status>true</status>
        <vserver>%(vserver_name)s</vserver>
      </fpolicy-policy-status-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>""" % {
    'policy_name': FPOLICY_POLICY_NAME,
    'vserver_name': VSERVER_NAME,
})

FAKE_VOL_XML = """<volume-info>
    <name>open123</name>
    <state>online</state>
    <size-total>0</size-total>
    <size-used>0</size-used>
    <size-available>0</size-available>
    <is-inconsistent>false</is-inconsistent>
    <is-invalid>false</is-invalid>
    </volume-info>"""

FAKE_XML1 = """<options>\
<test1>abc</test1>\
<test2>abc</test2>\
</options>"""

FAKE_XML2 = """<root><options>somecontent</options></root>"""

FAKE_NA_ELEMENT = api.NaElement(etree.XML(FAKE_VOL_XML))

FAKE_INVOKE_DATA = 'somecontent'

FAKE_XML_STR = 'abc'
FAKE_REST_CALL_STR = 'def'

FAKE_API_NAME = 'volume-get-iter'

FAKE_API_NAME_ELEMENT = api.NaElement(FAKE_API_NAME)

FAKE_NA_SERVER_STR = '127.0.0.1'

FAKE_NA_SERVER = api.NaServer(FAKE_NA_SERVER_STR)

FAKE_NA_SERVER_API_1_5 = api.NaServer(FAKE_NA_SERVER_STR)
FAKE_NA_SERVER_API_1_5.set_vfiler('filer')
FAKE_NA_SERVER_API_1_5.set_api_version(1, 5)


FAKE_NA_SERVER_API_1_14 = api.NaServer(FAKE_NA_SERVER_STR)
FAKE_NA_SERVER_API_1_14.set_vserver('server')
FAKE_NA_SERVER_API_1_14.set_api_version(1, 14)


FAKE_NA_SERVER_API_1_20 = api.NaServer(FAKE_NA_SERVER_STR)
FAKE_NA_SERVER_API_1_20.set_vfiler('filer')
FAKE_NA_SERVER_API_1_20.set_vserver('server')
FAKE_NA_SERVER_API_1_20.set_api_version(1, 20)


FAKE_QUERY = {'volume-attributes': None}

FAKE_DES_ATTR = {'volume-attributes': ['volume-id-attributes',
                                       'volume-space-attributes',
                                       'volume-state-attributes',
                                       'volume-qos-attributes']}

FAKE_CALL_ARGS_LIST = [mock.call(80), mock.call(8088), mock.call(443),
                       mock.call(8488)]

FAKE_RESULT_API_ERR_REASON = api.NaElement('result')
FAKE_RESULT_API_ERR_REASON.add_attr('errno', '000')
FAKE_RESULT_API_ERR_REASON.add_attr('reason', 'fake_reason')

FAKE_RESULT_API_ERRNO_INVALID = api.NaElement('result')
FAKE_RESULT_API_ERRNO_INVALID.add_attr('errno', '000')

FAKE_RESULT_API_ERRNO_VALID = api.NaElement('result')
FAKE_RESULT_API_ERRNO_VALID.add_attr('errno', '14956')

FAKE_RESULT_SUCCESS = api.NaElement('result')
FAKE_RESULT_SUCCESS.add_attr('status', 'passed')

FAKE_HTTP_SESSION = requests.Session()

FAKE_MANAGE_VOLUME = {
    'aggregate': SHARE_AGGREGATE_NAME,
    'name': SHARE_NAME,
    'owning-vserver-name': VSERVER_NAME,
    'junction_path': VOLUME_JUNCTION_PATH,
    'style': 'fake_style',
    'size': SHARE_SIZE,
}

FAKE_KEY_MANAGER_ERROR = "The onboard key manager is not enabled. To enable \
                         it, run \"security key-manager setup\"."

FAKE_ACTION_URL = '/endpoint'
FAKE_BASE_URL = '10.0.0.3/api'
FAKE_HTTP_BODY = {'fake_key': 'fake_value'}
FAKE_HTTP_QUERY = {'type': 'fake_type'}
FAKE_FORMATTED_HTTP_QUERY = "?type=fake_type"
FAKE_HTTP_HEADER = {"fake_header_key": "fake_header_value"}
FAKE_URL_PARAMS = {"fake_url_key": "fake_url_value_to_be_concatenated"}

FAKE_MIGRATION_RESPONSE_WITH_JOB = {
    "_links": {
        "self": {
            "href": "/api/resourcelink"
        }
    },
    "job": {
        "start_time": "2021-08-27T19:23:41.691Z",
        "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412",
        "description": "Fake Job",
        "state": "success",
        "message": "Complete: Successful",
        "end_time": "2021-08-27T19:23:41.691Z",
        "code": "0"
    }
}
FAKE_JOB_ID = FAKE_MIGRATION_RESPONSE_WITH_JOB['job']['uuid']
FAKE_MIGRATION_POST_ID = 'fake_migration_id'
FAKE_JOB_SUCCESS_STATE = {
    "_links": {
        "self": {
            "href": "/api/resourcelink"
        }
    },
    "start_time": "2021-08-27T19:23:41.691Z",
    "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412",
    "description": "POST migrations/%s" % FAKE_MIGRATION_POST_ID,
    "state": "success",
    "message": "Complete: Successful",
    "end_time": "2021-08-27T19:23:41.691Z",
    "code": "0"
}

FAKE_MIGRATION_JOB_SUCCESS = {
    "auto_cutover": True,
    "auto_source_cleanup": True,
    "current_operation": "none",
    "cutover_complete_time": "2020-12-02T18:36:19-08:00",
    "cutover_start_time": "2020-12-02T18:36:19-08:00",
    "cutover_trigger_time": "2020-12-02T18:36:19-08:00",
    "destination": {
        "ipspace": {
            "_links": {
                "self": {
                    "href": "/api/resourcelink"
                }
            },
            "name": "exchange",
            "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412"
        },
        "volume_placement": {
            "aggregates": [
                {
                    "_links": {
                        "self": {
                            "href": "/api/resourcelink"
                        }
                    },
                    "name": "aggr1",
                    "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412"
                }
            ],
            "volumes": [
                {
                    "aggregate": {
                        "_links": {
                            "self": {
                                "href": "/api/resourcelink"
                            }
                        },
                        "name": "aggr1",
                        "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412"
                    },
                    "volume": {
                        "_links": {
                            "self": {
                                "href": "/api/resourcelink"
                            }
                        },
                        "name": "this_volume",
                        "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412"
                    }
                }
            ]
        }
    },
    "end_time": "2020-12-02T18:36:19-08:00",
    "last_failed_state": "precheck_started",
    "last_operation": "none",
    "last_pause_time": "2020-12-02T18:36:19-08:00",
    "last_resume_time": "2020-12-02T18:36:19-08:00",
    "messages": [
        {
            "code": 852126,
            "message": "SVM migrate cannot start since a volume move is "
                       "running.""Retry the command once volume move has "
                       "finished."
        }
    ],
    "point_of_no_return": True,
    "restart_count": 0,
    "source": {
        "cluster": {
            "_links": {
                "self": {
                    "href": "/api/resourcelink"
                }
            },
            "name": "cluster1",
            "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412"
        },
        "svm": {
            "_links": {
                "self": {
                    "href": "/api/resourcelink"
                }
            },
            "name": "svm1",
            "uuid": "02c9e252-41be-11e9-81d5-00a0986138f7"
        }
    },
    "start_time": "2020-12-02T18:36:19-08:00",
    "state": "migrate_complete",
    "uuid": "4ea7a442-86d1-11e0-ae1c-123478563412"
}


VOLUME_GET_ITER_STATE_RESPONSE = etree.XML("""
    <results status="passed">
        <num-records>1</num-records>
        <attributes-list>
            <volume-attributes>
                <volume-state-attributes>
                    <state>online</state>
                </volume-state-attributes>
            </volume-attributes>
        </attributes-list>
    </results>
""")

ASYNC_OPERATION_RESPONSE = etree.XML("""
  <results status="passed">
    <result-status>in_progress</result-status>
    <result-jobid>123</result-jobid>
  </results>
""")

VOLUME_GET_ITER_STYLE_FLEXGROUP_RESPONSE = etree.XML("""
    <results status="passed">
        <num-records>1</num-records>
        <attributes-list>
            <volume-attributes>
                <volume-id-attributes>
                    <style-extended>%(style)s</style-extended>
                </volume-id-attributes>
            </volume-attributes>
        </attributes-list>
    </results>
""" % {
    'style': FLEXGROUP_STYLE_EXTENDED,
})

VOLUME_GET_ITER_STYLE_FLEXVOL_RESPONSE = etree.XML("""
    <results status="passed">
        <num-records>1</num-records>
        <attributes-list>
            <volume-attributes>
                <volume-id-attributes>
                    <style-extended>flexvol</style-extended>
                </volume-id-attributes>
            </volume-attributes>
        </attributes-list>
    </results>
""")

JOB_GET_STATE_RESPONSE = etree.XML("""
    <results status="passed">
        <num-records>1</num-records>
        <attributes-list>
            <job-info>
                <job-state>%(state)s</job-state>
            </job-info>
        </attributes-list>
    </results>
""" % {
    'state': JOB_STATE,
})

JOB_GET_STATE_NOT_UNIQUE_RESPONSE = etree.XML("""
    <results status="passed">
        <num-records>1</num-records>
        <attributes-list>
            <job-info>
                <job-state>%(state)s</job-state>
            </job-info>
            <job-info>
                <job-state>%(state)s</job-state>
            </job-info>
        </attributes-list>
    </results>
""" % {
    'state': JOB_STATE,
})

NO_RECORDS_RESPONSE_REST = {
    "records": [],
    "num_records": 0,
    "_links": {
        "self": {
            "href": "/api/cluster/nodes"
        }
    }
}

ERROR_RESPONSE_REST = {
    "error": {
        "code": 1100,
        "message": "fake error",
    }
}

GET_VERSION_RESPONSE_REST = {
    "records": [
        {
            "version": {
                "generation": "9",
                "minor": "11",
                "major": "1",
                "full": "NetApp Release 9.11.1: Sun Nov 05 18:20:57 UTC 2017"
            }
        }
    ],
    "_links": {
        "next": {
            "href": "/api/resourcelink"
        },
        "self": {
            "href": "/api/resourcelink"
        }
    },
    "num_records": 0
}

VOLUME_GET_ITER_RESPONSE_LIST_REST = [
    {
        "uuid": "2407b637-119c-11ec-a4fb-00a0b89c9a78",
        "name": VOLUME_NAMES[0],
        "state": "online",
        "style": "flexvol",
        "is_svm_root": False,
        "type": "rw",
        "error_state": {
            "is_inconsistent": False
        },
        "_links": {
            "self": {
                "href": "/api/storage/volumes/2407b637-119c-11ec-a4fb"
            }
        }
    },
    {
        "uuid": "2c190609-d51c-11eb-b83a",
        "name": VOLUME_NAMES[1],
        "state": "online",
        "style": "flexvol",
        "is_svm_root": False,
        "type": "rw",
        "error_state": {
            "is_inconsistent": False
        },
        "_links": {
            "self": {
                "href": "/api/storage/volumes/2c190609-d51c-11eb-b83a"
            }
        }
    }
]

VOLUME_GET_ITER_RESPONSE_REST_PAGE = {
    "records": [
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
    ],
    "num_records": 10,
    "_links": {
        "self": {
            "href": "/api/storage/volumes?fields=name&max_records=2"
        },
        "next": {
            "href": "/api/storage/volumes?"
            f"start.uuid={VOLUME_GET_ITER_RESPONSE_LIST_REST[0]['uuid']}"
            "&fields=name&max_records=2"
        }
    }
}

VOLUME_GET_ITER_RESPONSE_REST_LAST_PAGE = {
    "records": [
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
        VOLUME_GET_ITER_RESPONSE_LIST_REST[0],
    ],
    "num_records": 8,
}

INVALID_GET_ITER_RESPONSE_NO_RECORDS_REST = {
    "num_records": 1,
}

INVALID_GET_ITER_RESPONSE_NO_NUM_RECORDS_REST = {
    "records": [],
}

JOB_RESPONSE_REST = {
    "job": {
        "uuid": "uuid-12345",
        "_links": {
            "self": {
                "href": "/api/cluster/jobs/uuid-12345"
            }
        }
    }
}

JOB_SUCCESSFUL_REST = {
    "uuid": FAKE_UUID,
    "description": "Fake description",
    "state": "success",
    "message": "success",
    "code": 0,
    "start_time": "2022-02-18T20:08:03+00:00",
    "end_time": "2022-02-18T20:08:04+00:00",
}

JOB_RUNNING_REST = {
    "uuid": FAKE_UUID,
    "description": "Fake description",
    "state": "running",
    "message": "running",
    "code": 0,
}

JOB_ERROR_REST = {
    "uuid": FAKE_UUID,
    "description": "Fake description",
    "state": "failure",
    "message": "failure",
    "code": 4,
    "error": {
        "target": "uuid",
        "arguments": [
            {
                "message": "string",
                "code": "string"
            }
        ],
        "message": "entry doesn't exist",
        "code": "4"
    },
    "start_time": "2022-02-18T20:08:03+00:00",
    "end_time": "2022-02-18T20:08:04+00:00",
}

FAKE_GET_ONTAP_VERSION_REST = {
    "version": {
        "full": "NetApp Release 9.10.1RC1: Wed Oct 27 02:46:19 UTC 2021",
        "generation": 9,
        "major": 10,
        "minor": 1
    },
}

FAKE_GET_CLUSTER_NODE_VERSION_REST = {
    "records": [
        {
            "uuid": "fake_uuid",
            "name": CLUSTER_NAME,
            "version": FAKE_GET_ONTAP_VERSION_REST["version"],
        }
    ],
}

FAKE_GET_LICENSES_REST = {
    "records": [
        {
            "name": "base",
        },
        {
            "name": "nfs",
        },
        {
            "name": "cifs",
        }
    ],
    "num_records": 3,
}

VOLUME_ITEM_SIMPLE_RESPONSE_REST = {
    "uuid": "fake_uuid",
    "name": VOLUME_NAMES[0],
    "style": 'flexvol',
    "svm": {
        "name": VSERVER_NAME,
        "uuid": "fake_uuid",
        },
    "efficiency": {
        "state": "enabled",
        "compression": "true"
    },
    "state": "online",
}

VOLUME_LIST_SIMPLE_RESPONSE_REST = {
    "records": [
        VOLUME_ITEM_SIMPLE_RESPONSE_REST
    ],
    "num_records": 1,
}

SVMS_LIST_SIMPLE_RESPONSE_REST = {
    "records": [
        {
            "uuid": "fake_uuid",
            "name": VSERVER_NAME,
            "subtype": VSERVER_TYPE_DEFAULT,
            "state": VSERVER_STATE,
        },
        {
            "uuid": "fake_uuid_2",
            "name": VSERVER_NAME_2,
            "subtype": VSERVER_TYPE_DEFAULT,
            "state": VSERVER_STATE,
        },
    ],
    "num_records": 2,
}

AGGR_GET_ITER_RESPONSE_REST = {
    "records": [
        {
            "uuid": "fake_uuid_1",
            "name": "fake_aggr1",
            "home_node": {
                "name": "fake_home_node_name"
            },
            "space": {
                "footprint": 702764609536,
                "footprint_percent": 55,
                "block_storage": {
                    "size": 1271819509760,
                    "available": 568692293632,
                    "used": 703127216128,
                },
                "snapshot": {
                    "used_percent": 0,
                    "available": 0,
                    "total": 0,
                    "used": 0,
                    "reserve_percent": 0
                },
                "cloud_storage": {
                    "used": 0
                },
                "efficiency": {
                    "savings": 70597836800,
                    "ratio": 11.00085294873662,
                    "logical_used": 77657018368
                },
                "efficiency_without_snapshots": {
                    "savings": 4288385024,
                    "ratio": 1.614324692241794,
                    "logical_used": 11269033984
                },
                "efficiency_without_snapshots_flexclones": {
                    "savings": 4288385024,
                    "ratio": 1.614324692241794,
                    "logical_used": 11269033984
                }
            },
            "block_storage": {
                "storage_type": "vmdisk",
                "primary": {
                    "raid_type": "raid0"
                }
            },
        },
        {
            "uuid": "fake_uuid_2",
            "name": "fake_aggr2",
            "home_node": {
                "name": "fake_home_node_name"
            },
            "space": {
                "footprint": 699261227008,
                "footprint_percent": 49,
                "block_storage": {
                    "size": 1426876227584,
                    "available": 727211110400,
                    "used": 699665117184,
                },
                "snapshot": {
                    "used_percent": 0,
                    "available": 0,
                    "total": 0,
                    "used": 0,
                    "reserve_percent": 0
                },
                "cloud_storage": {
                    "used": 0
                },
                "efficiency": {
                    "savings": 4173848576,
                    "ratio": 1.447821420943505,
                    "logical_used": 13494190080
                },
                "efficiency_without_snapshots": {
                    "savings": 0,
                    "ratio": 1,
                    "logical_used": 8565026816
                },
                "efficiency_without_snapshots_flexclones": {
                    "savings": 0,
                    "ratio": 1,
                    "logical_used": 8565026816
                }
            },
            "block_storage": {
                "storage_type": "vmdisk",
                "primary": {
                    "raid_type": "raid0"
                }
            },
        }
    ],
    "num_records": 2,
}

EFFECTIVE_TYPE = 'fake_effective_type1'
DISK_LIST_SIMPLE_RESPONSE_REST = {
    "records": [
        {
            "name": "NET-1.2",
            "effective_type": EFFECTIVE_TYPE,
        }
    ],
    "num_records": 1,
}

GENERIC_JOB_POST_RESPONSE = {
    "job": {
        "_links": {
            "self": {
                "href": "/api/resourcelink"
            }
        },
        "uuid": "fake_uuid"
    }
}

GENERIC_NETWORK_INTERFACES_GET_REPONSE = {
    "records": [
        {
            "uuid": "fake_uuid",
            "name": LIF_NAME,
            "ip": {
                "address": IP_ADDRESS,
                "netmask": NETMASK
            },
            "svm": {
                "name": VSERVER_NAME
            },
            "services": [
                "data_nfs",
                "data_cifs",
            ],
            "location": {
                "home_node": {
                    "name": CLUSTER_NAME
                },
                "home_port": {
                    "name": PORT
                }
            }
        }
    ],
    "num_records": 1,
}

GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES = {
    "records": [
        {
            "svm": {
                "uuid": "fake_uuid",
                "name": VSERVER_NAME,
            },
            "efficiency": {
                "volume_path": VOLUME_JUNCTION_PATH
            },
            "id": "fake-policy-uuid",
            "name": EXPORT_POLICY_NAME,
            "style": "flexvol",
            "type": "rw",
            "aggregates": [
                {
                    "name": SHARE_AGGREGATE_NAME
                }
            ],
            "nas": {
                "path": VOLUME_JUNCTION_PATH
            },
            "space": {
                "size": 21474836480
            },
        }
    ],
    "num_records": 1,
}

GENERIC_FPOLICY_RESPONSE = {
    "records": [
        {
            "name": FPOLICY_POLICY_NAME,
            "enabled": "true",
            "priority": 1,
            "events": [
                {
                    "name": FPOLICY_EVENT_NAME,
                }
            ],
            "engine": {
                "name": FPOLICY_ENGINE,
            },
            "scope": {
                "include_shares": [
                    VOLUME_NAMES[0]
                ],
                "include_extension": FPOLICY_EXT_TO_INCLUDE_LIST,
                "exclude_extension": FPOLICY_EXT_TO_EXCLUDE_LIST
            },
        }
    ],
    "num_records": 1,
}

GENERIC_FPOLICY_EVENTS_RESPONSE = {
    "records": [
        {
            "name": FPOLICY_EVENT_NAME,
            "protocol": FPOLICY_PROTOCOL,
            "file_operations": {
                "create": 'true',
                "write": 'true',
                "rename": 'true'
            },
        }
    ],
    "num_records": 1,
}

EXPORT_POLICY_REST = {
    "records": [
        {
            "_links": {
                "self": {
                    "href": "/api/resourcelink"
                }
            },
            "name": "string",
            "id": 0,
            "svm": {
                "_links": {
                    "self": {
                        "href": "/api/resourcelink"
                    }
                },
                "name": "svm1",
                "uuid": "02c9e252-41be-11e9-81d5-00a0986138f7"
            },
            "rules": [{
                "rw_rule": [
                    "any"
                ],
                "_links": {
                    "self": {
                        "href": "/api/resourcelink"
                    }
                },
                "ro_rule": [
                    "any"
                ],
                "allow_suid": True,
                "chown_mode": "restricted",
                "index": 0,
                "superuser": [
                    "any"
                ],
                "protocols": [
                    "any"
                ],
                "anonymous_user": "string",
                "clients": [
                    {"match": "0.0.0.0/0"}
                ],
                "ntfs_unix_security": "fail",
                "allow_device_creation": True
            }]
        }],
    "_links": {
        "next": {
            "href": "/api/resourcelink"
        },
        "self": {
            "href": "/api/resourcelink"
        }
    },
    "num_records": 1
}

QOS_POLICY_GROUP_REST = {
    "records": [
        {
            "policy_class": "undefined",
            "object_count": '0',
            "fixed": {
                "max_throughput_iops": 0,
                "capacity_shared": True,
                "max_throughput_mbps": 0,
                "min_throughput_iops": 0,
                "min_throughput_mbps": 0
            },
            "_links": {
                "self": {
                    "href": "/api/resourcelink"
                }
            },
            "name": "extreme",
            "adaptive": {
                "expected_iops_allocation": "allocated_space",
                "expected_iops": 0,
                "peak_iops_allocation": "used_space",
                "block_size": "any",
                "peak_iops": 0,
                "absolute_min_iops": 0
            },
            "uuid": "1cd8a442-86d1-11e0-ae1c-123478563412",
            "svm": {
                "_links": {
                    "self": {
                        "href": "/api/resourcelink"
                    }
                },
                "name": "svm1",
                "uuid": "02c9e252-41be-11e9-81d5-00a0986138f7"
            },
            "pgid": 0,
            "scope": "cluster"
        }
    ],
    "_links": {
        "next": {
            "href": "/api/resourcelink"
        },
        "self": {
            "href": "/api/resourcelink"
        }
    },
    "error": {
        "target": "uuid",
        "arguments": [
            {
                "message": "string",
                "code": "string"
            }
        ],
        "message": "entry doesn't exist",
        "code": "4"
    },
    "num_records": 1
}

FAKE_SNAPSHOT_UUID = "fake_uuid"
FAKE_VOLUME_UUID = "fake_volume_uuid"
SNAPSHOT_REST = {
    "name": SNAPSHOT_NAME,
    "uuid": FAKE_SNAPSHOT_UUID,
    "volume": {
        "name": VOLUME_NAMES[0],
        "uuid": FAKE_VOLUME_UUID,
    },
    "create_time": "2019-02-04T19:00:00Z",
    "owners": ["volume_clone"],
    "svm": {
        "name": VSERVER_NAME,
    }
}

SNAPSHOTS_REST_RESPONSE = {
    "records": [
        SNAPSHOT_REST,
    ],
    "num_records": 1,
}

SNAPSHOTS_MULTIPLE_REST_RESPONSE = {
    "records": [
        SNAPSHOT_REST,
        SNAPSHOT_REST,
    ],
    "num_records": 2,
}

SNAPMIRROR_GET_ITER_RESPONSE_REST = {
    "records": [
        {
            "uuid": FAKE_UUID,
            "source": {
                "path": SM_SOURCE_VSERVER + ':' + SM_SOURCE_VOLUME,
                "svm": {
                    "name": SM_SOURCE_VSERVER
                }
            },
            "destination": {
                "path": SM_DEST_VSERVER + ':' + SM_DEST_VOLUME,
                "svm": {
                    "name": SM_DEST_VSERVER
                }
            },
            "policy": {
                "type": "async"
            },
            "state": "snapmirrored",
            "healthy": True,
            "transfer_schedule": {
                "name": "hourly",
            },
            "transfer": {
                "state": "success"
            }
        }
    ],
    "num_records": 1,
}

REST_GET_SNAPMIRRORS_RESPONSE = [{
    'destination-volume': SM_DEST_VOLUME,
    'destination-vserver': SM_DEST_VSERVER,
    'last-transfer-end-timestamp': 0,
    'mirror-state': 'snapmirrored',
    'relationship-status': 'idle',
    'source-volume': SM_SOURCE_VOLUME,
    'source-vserver': SM_SOURCE_VSERVER,
    'uuid': FAKE_UUID,
    'policy-type': 'async',
    'schedule': 'hourly',
    'transferring-state': 'success'
}]

FAKE_CIFS_RECORDS = {
    "records": [
        {
            "svm": {
                "uuid": "000c5cd2-ebdf-11e8-a96e-0050568ea3cb",
                "name": "vs1"
            },
            "user_or_group": "Everyone",
            "permission": "full_control"
        },
        {
            "svm": {
                "uuid": "000c5cd2-ebdf-11e8-a96e-0050568ea3cb",
                "name": "vs1"
            },
            "user_or_group": "root",
            "permission": "no_access"
        }
    ],
    "num_records": 2
}

FAKE_VOL_MOVE_STATUS = {
    "records": [
        {
            "svm": {
                "_links": {
                    "self": {
                        "href": "/api/resourcelink"
                    }
                },
                "name": "fake_svm",
                "uuid": "02c9e252-41be-11e9-81d5-00a0986138f7"
            },
            "uuid": "fake_uuid",
            "name": "fake_name",
            "movement": {
                "state": "success",
                "percent_complete": 100
            },
        }
    ],
    "num_records": 1,
}

REST_SIMPLE_RESPONSE = {
    "records": [
        {
            'uuid': FAKE_UUID
        }
    ]
}

FAKE_GET_VOLUME_CLONE_REST = [
    {
        "uuid": FAKE_UUID,
        "name": VOLUME_NAMES[0],
        "clone": {
            "parent_volume": {
                "name": VOLUME_NAMES[1]
            }
        },
        "num_records": 1,
    }
]

VSERVER_DATA_LIST_RESPONSE_REST = {
    'records': [
        {
            'name': VSERVER_NAME
        },
        {
            'name': VSERVER_NAME_2
        }
    ],
    'num_records': 2,
}

PERF_COUNTER_LIST_INFO_WAFL_RESPONSE_REST = {
    'name': 'wafl',
    'counter_schemas': [
        {
            'name': 'cp_phase_times',
            'description': 'Array of percentage time spent in different phases'
                           + ' of Consistency Point (CP).',
            'type': 'percent',
            'unit': 'percent',
            'denominator': {
                'name': 'total_cp_msecs'
            }
        }
    ],
}

PERF_COUNTER_TOTAL_CP_MSECS_LABELS_REST = [
    'cp_setup', 'cp_pre_p0', 'cp_p0_snap_del', 'cp_p1_clean', 'cp_p1_quota',
    'cp_ipu_disk_add', 'cp_p2v_inofile', 'cp_p2v_ino_pub', 'cp_p2v_ino_pri',
    'cp_p2v_fsinfo', 'cp_p2v_dlog1', 'cp_p2v_dlog2', 'cp_p2v_refcount',
    'cp_p2v_topaa', 'cp_p2v_df_scores_sub', 'cp_p2v_bm', 'cp_p2v_snap',
    'cp_p2v_df_scores', 'cp_p2v_volinfo', 'cp_p2v_cont', 'cp_p2a_inofile',
    'cp_p2a_ino', 'cp_p2a_dlog1', 'cp_p2a_hya', 'cp_p2a_dlog2',
    'cp_p2a_fsinfo', 'cp_p2a_ipu_bitmap_grow', 'cp_p2a_refcount',
    'cp_p2a_topaa', 'cp_p2a_hyabc', 'cp_p2a_bm', 'cp_p2a_snap',
    'cp_p2a_volinfo', 'cp_p2_flush', 'cp_p2_finish', 'cp_p3_wait',
    'cp_p3v_volinfo', 'cp_p3a_volinfo', 'cp_p3_finish', 'cp_p4_finish',
    'cp_p5_finish',
]

PERF_COUNTER_TOTAL_CP_MSECS_LABELS_RESULT = [
    label[3:] for label in PERF_COUNTER_TOTAL_CP_MSECS_LABELS_REST
]

PERF_COUNTER_TOTAL_CP_MSECS_VALUES_REST = [
    0, 3112, 3, 0, 0, 3, 757, 0, 99, 0, 26, 0, 22, 1, 0, 194, 4, 224, 359, 222,
    0, 0, 0, 0, 0, 0, 82, 0, 0, 0, 0, 0, 0, 62, 0, 133, 16, 35, 334219, 43,
    2218, 20, 0,
]

PERF_COUNTER_TABLE_ROWS_WAFL = {
    'records': [
        {
            'id': NODE_NAME + ':wafl',
            'counters': [
                {
                    'name': 'cp_phase_times',
                    'values': PERF_COUNTER_TOTAL_CP_MSECS_VALUES_REST,
                    'labels': PERF_COUNTER_TOTAL_CP_MSECS_LABELS_REST
                }
            ],
        }
    ],
    'num_records': 1,
}

PERF_COUNTER_DOMAIN_BUSY_LABELS = [
    'exempt', 'ha', 'host_os', 'idle', 'kahuna', 'kahuna_legacy', 'none',
    'nwk_exempt', 'network', 'protocol', 'raid', 'raid_exempt', 'sm_exempt',
    'ssan_exempt', 'storage', 'target', 'unclassified', 'wafl_exempt',
    'wafl_mpcleaner', 'xor_exempt', 'ssan_exempt2', 'exempt_ise', 'zombie',
]

PERF_COUNTER_DOMAIN_BUSY_VALUES_1 = [
    83071627197, 1334877, 19459898, 588539096, 11516887, 14878622, 18,
    647698, 20, 229232646, 4310322, 441035, 12946782, 57837913, 38765442,
    1111004351701, 1497335, 949657, 109890, 768027, 21, 14, 13
]

PERF_COUNTER_DOMAIN_BUSY_VALUES_2 = [
    1191129018056, 135991, 22842513, 591213798, 9449562, 15345460, 0,
    751656, 0, 162605694, 3927323, 511160, 7644403, 29696759, 21787992,
    3585552592, 1058902, 957296, 87811, 499766, 0, 0, 0
]

PERF_COUNTER_ELAPSED_TIME_1 = 1199265469753
PERF_COUNTER_ELAPSED_TIME_2 = 1199265469755

PERF_GET_INSTANCES_PROCESSOR_RESPONSE_REST = {
    'records': [
        {
            'counter_table': {
                'name': 'processor'
            },
            'id': NODE_NAME + ':processor0',
            'counters': [
                {
                    'name': 'domain_busy_percent',
                    'values': PERF_COUNTER_DOMAIN_BUSY_VALUES_1,
                    'labels': PERF_COUNTER_DOMAIN_BUSY_LABELS
                },
                {
                    'name': 'elapsed_time',
                    'value': PERF_COUNTER_ELAPSED_TIME_1,
                }
            ],
        },
        {
            'counter_table': {
                'name': 'processor'
            },
            'id': NODE_NAME + ':processor1',
            'counters': [
                {
                    'name': 'domain_busy_percent',
                    'values': PERF_COUNTER_DOMAIN_BUSY_VALUES_2,
                    'labels': PERF_COUNTER_DOMAIN_BUSY_LABELS
                },
                {
                    'name': 'elapsed_time',
                    'value': PERF_COUNTER_ELAPSED_TIME_2,
                }
            ],
        }
    ],
    'num_records': 2,
}

PERF_COUNTERS_PROCESSOR_EXPECTED = [
    {
        'instance-name': 'processor',
        'instance-uuid': NODE_NAME + ':processor0',
        'node-name': NODE_NAME,
        'timestamp': mock.ANY,
        'domain_busy':
            ','.join([str(v) for v in PERF_COUNTER_DOMAIN_BUSY_VALUES_1])
    },
    {
        'instance-name': 'processor',
        'instance-uuid': NODE_NAME + ':processor0',
        'node-name': NODE_NAME,
        'timestamp': mock.ANY,
        'processor_elapsed_time': PERF_COUNTER_ELAPSED_TIME_1
    },
    {
        'instance-name': 'processor',
        'instance-uuid': NODE_NAME + ':processor1',
        'node-name': NODE_NAME,
        'timestamp': mock.ANY,
        'domain_busy':
            ','.join([str(v) for v in PERF_COUNTER_DOMAIN_BUSY_VALUES_2])
    },
    {
        'instance-name': 'processor',
        'instance-uuid': NODE_NAME + ':processor1',
        'node-name': NODE_NAME,
        'timestamp': mock.ANY,
        'processor_elapsed_time': PERF_COUNTER_ELAPSED_TIME_2
    },
]

DELETED_EXPORT_POLICY_GET_ITER_RESPONSE_REST = {
    'records': [
        {
            'name': DELETED_EXPORT_POLICIES[VSERVER_NAME][0],
            'svm': {'name': VSERVER_NAME},
        },
        {
            'name': DELETED_EXPORT_POLICIES[VSERVER_NAME][1],
            'svm': {'name': VSERVER_NAME},
        },
        {
            'name': DELETED_EXPORT_POLICIES[VSERVER_NAME_2][0],
            'svm': {'name': VSERVER_NAME_2},
        }
    ],
    'num_records': 3
}

SECUTITY_KEY_MANAGER_SUPPORT_RESPONSE_TRUE_REST = {
    'records': [
        {
            'volume_encryption': {
                'supported': True,
                'message': '',
                'code': 0
            }
        }
    ],
    'num_records': 1
}

SECUTITY_KEY_MANAGER_SUPPORT_RESPONSE_FALSE_REST = {
    'records': [
        {
            'volume_encryption': {
                'supported': False,
                'message': 'No platform support for volume encryption '
                           'in following nodes - node1, node2.',
                'code': 346758
            }
        }
    ],
    'num_records': 1
}

NFS_CONFIG_DEFAULT_RESULT_REST = {
    'records': [
        {
            'svm': {
                'uuid': FAKE_UUID,
                'name': VSERVER_NAME,
            },
            'transport': {
                'udp_enabled': True,
                'tcp_enabled': True,
                'tcp_max_transfer_size': 65536
            },
        }
    ],
    'num_records': 1,
}

DNS_REST_RESPONSE = {
    "domains": [
        "example.com",
        "example2.example3.com"
    ],
    "dynamic_dns": {
        "fqdn": "example.com",
        "time_to_live": "P2D",
        "use_secure": "true",
        "enabled": "true"
    },
    "servers": [
        "10.224.65.20",
        "2001:db08:a0b:12f0::1"
    ],
}

SVM_ITEM_SIMPLE_RESPONSE_REST = {
    "uuid": "fake_uuid",
    "name": VSERVER_NAME,
}

LOCAL_USERS_CIFS_RESPONSE = {
    "sid": "fake_SID",
    "svm": {
        "name": "svm1",
        "uuid": "02c9e252-41be-11e9-81d5-00a0986138f7"
    }
}

PREFERRED_DC_REST = {
    "fqdn": "test.com",
    "server_ip": "4.4.4.4"
}

FAKE_VSERVER_PEERS = [{
    'uuid': 'fake_uuid'
    }]


FAKE_PEER_GET_RESPONSE = {
    'records': [
        {
            'uuid': FAKE_UUID,
            'svm': {
                'name': VSERVER_NAME,
            },
            'peer': {
                'svm': {
                    'name': VSERVER_NAME_2
                },
                'cluster': {
                    'name': CLUSTER_NAME
                }
            },
            'state': VSERVER_PEER_STATE,
        }
    ],
    'num_records': 1
}

REST_SPEED_SORTED_PORTS = [
    {'node': NODE_NAME, 'port': 'e0d', 'speed': '10000'},
    {'node': NODE_NAME, 'port': 'e0c', 'speed': '1000'},
    {'node': NODE_NAME, 'port': 'e0b', 'speed': '100'},
]

REST_SPEED_NOT_SORTED_PORTS = [
    {'node': NODE_NAME, 'port': 'e0b', 'speed': 100},
    {'node': NODE_NAME, 'port': 'e0c', 'speed': 1000},
    {'node': NODE_NAME, 'port': 'e0d', 'speed': 10000},
]

REST_ETHERNET_PORTS = {
    "records": [
        {
            "uuid": "fake_uuid1",
            "name": "e0a",
            "type": "physical",
            "node": {
                "name": NODE_NAME
            },
            "broadcast_domain": {
                "name": "fake_domain_1",
                "ipspace": {
                    "name": "Default"
                }
            },
            "state": "up",
            "speed": 10,
        },
        {
            "uuid": "fake_uuid2",
            "name": "e0b",
            "type": "physical",
            "node": {
                "name": NODE_NAME
            },
            "broadcast_domain": {
                "name": "fake_domain_2",
                "ipspace": {
                    "name": "Default"
                }
            },
            "state": "up",
            "speed": 100,
        },
        {
            "uuid": "fake_uuid3",
            "name": "e0c",
            "type": "physical",
            "node": {
                "name": NODE_NAME
            },
            "broadcast_domain": {
                "name": "fake_domain_3",
                "ipspace": {
                    "name": "Default"
                }
            },
            "state": "up",
            "speed": 1000,
        },
        {
            "uuid": "fake_uuid4",
            "name": "e0d",
            "type": "physical",
            "node": {
                "name": NODE_NAME
            },
            "broadcast_domain": {
                "name": "fake_domain_4",
                "ipspace": {
                    "name": "Default"
                }
            },
            "state": "up",
            "speed": 10000,
        }
    ],
}

SVM_ITEM_SIMPLE_RESPONSE_REST = {
    "uuid": "fake_uuid",
    "name": VSERVER_NAME,
}

FAKE_GET_BROADCAST_DOMAIN = {
    'records': [
        {
            'ports': [
                {
                    'name': PORT,
                    'node': {'name': NODE_NAME}
                }
            ],
            'name': BROADCAST_DOMAIN,
            'ipspace': {'name': IPSPACE_NAME}
        }
    ]
}

NFS_CONFIG_RESULT_REST = {
    'records': [
        {
            'svm': {
                'uuid': FAKE_UUID,
                'name': VSERVER_NAME,
            },
            'transport': {
                'udp_enabled': True,
                'tcp_enabled': True,
                'tcp_max_transfer_size': 65536
            },
        }
    ],
    'num_records': 1,
}

SERVICE_POLICIES_REST = {
    'records': [
        {
            'uuid': 'fake_policy_uuid',
            'name': 'default-data-files',
            'svm': {
                'name': VSERVER_NAME
            },
            'services': [
                'data_core',
                'data_flexcache',
                'data_fpolicy_client',
                'management_dns_client',
                'management_ad_client',
                'management_ldap_client',
                'management_nis_client',
                'data_dns_server'
            ],
        },
    ],
    'num_records': 1,
}

SECURITY_CERT_GET_RESPONSE_REST = {
    'records': [
        {
            'uuid': 'fake_cert_uuid',
            'serial_number': 'fake_serial_number',
            'key_size': 0,
            'hash_function': "sha256",
            'common_name': "fake_common_name",
            'name': "cert1",
            'ca': 'fake_ca',
            'expiry_time': 'fake_expiry_time',
            'svm': {
                'name': VSERVER_NAME,
                'uuid': 'fake_uuid',
            },
        },
    ],
    'num_records': 1,
}

SECURITY_CERT_POST_RESPONSE_REST = {
    'records': [
        {
            'uuid': 'fake_cert_uuid',
            'serial_number': 'fake_serial_number',
            'key_size': 0,
            'hash_function': "sha256",
            'common_name': "fake_common_name",
            'name': "cert1",
            'ca': 'fake_ca',
            'expiry_time': 'fake_expiry_time',
            'svm': {
                'name': VSERVER_NAME,
                'uuid': 'fake_uuid',
            },
        },
    ],
    'num_records': 1,
}

GET_SNAPMIRROR_POLICIES_REST = {

    "records": [
        {
            "uuid": FAKE_UUID,
            "name": SNAPMIRROR_POLICY_NAME
        }],
    'num_records': 1,
}

REST_VSERVER_GET_IPSPACE_NAME_RESPONSE = {
    "records": [
        {
            "uuid": FAKE_UUID,
            "ipspace": {'name': IPSPACE_NAME}
        }
    ],
    'num_records': 1,
}

BROADCAST_DOMAIN_LIST_SIMPLE_RESPONSE_REST = {
    "records": [
        {
            "ports": [
                {
                    "_links": {
                        "self": {
                            "href": FAKE_BASE_URL
                        }
                    },
                    "name": "fake_port_name",
                    "uuid": FAKE_UUID,
                    "node": {
                        "name": "fake_node_name"
                    }
                }
            ],
            "_links": {
                "self": {
                    "href": FAKE_BASE_URL
                }
            },
            "name": "fake_broadcast_name",
            "ipspace": {
                "_links": {
                    "self": {
                        "href": FAKE_BASE_URL
                    }
                },
                "name": IPSPACE_NAME,
                "uuid": FAKE_UUID
            },
            "uuid": FAKE_UUID,
            "mtu": MTU
        }
    ],
    "_links": {
        "next": {
            "href": FAKE_BASE_URL
        },
        "self": {
            "href": FAKE_BASE_URL
        }
    },
    "num_records": 1
}

GET_IPSPACES_RESPONSE = {
    'ipspace': IPSPACE_NAME,
    'uuid': FAKE_UUID,
    'broadcast-domains': [BROADCAST_DOMAIN],
    'ports': [PORT],
    'vservers': [VSERVER_NAME, VSERVER_NAME_2]
}

IPSPACE_INFO = {
    'records': [
        {
            'name': IPSPACE_NAME,
            'uuid': FAKE_UUID
        }
    ]
}

REST_SINGLE_PORT = {
    "records": [
        {
            "uuid": "fake_uuid1",
            "name": "e0a",
            "type": "physical",
            "node": {
                "name": NODE_NAME
            },
            "broadcast_domain": {
                "name": "fake_domain_1",
                "ipspace": {
                    "name": "Default"
                }
            },
            "state": "up",
            "speed": 10,
        }
    ]
}

VOLUME = {
    "name": "fake_volume_name",
    "uuid": "028baa66-41bd-11e9-81d5-00a0986138f7",
    "max_dir_size": 0,
}

SECUTITY_KEY_MANAGER_SUPPORT_RESPONSE_TRUE_REST = {
    'records': [
        {
            'volume_encryption': {
                'supported': True,
                'message': '',
                'code': 0
            }
        }
    ],
    'num_records': 1
}

SECUTITY_KEY_MANAGER_SUPPORT_RESPONSE_FALSE_REST = {
    'records': [
        {
            'volume_encryption': {
                'supported': False,
                'message': 'No platform support for volume encryption '
                           'in following nodes - node1, node2.',
                'code': 346758
            }
        }
    ],
    'num_records': 1
}

FAKE_DISK_TYPE_RESPONSE = {
    "records": [
        {
            "effective_type": "fakedisk"
        }
    ]
}

FAKE_SVM_AGGREGATES = {
    "records": [
        {
            "name": VSERVER_NAME,
            "aggregates": [
                {
                    "name": SHARE_AGGREGATE_NAMES_LIST[0],
                    "available_size": 568692293632
                },
                {
                    "name": SHARE_AGGREGATE_NAMES_LIST[1],
                    "available_size": 727211110400
                },
            ]
        }
    ]
}

FAKE_AGGREGATES_RESPONSE = {
    "records": [
        {
            "aggregates": [
                {
                    "name": SHARE_AGGREGATE_NAME
                }
            ],
            "name": VSERVER_NAME,
        }
    ]
}

FAKE_SVM_AGGR_EMPTY = {
    "records": [
        {
            "name": VSERVER_NAME,
            "aggregates": []
        }
    ]
}

FAKE_AGGR_LIST = {
    "records": [
        {
            "name": SHARE_AGGREGATE_NAMES_LIST[0]
        }
    ]
}

REST_MGMT_INTERFACES = {
    "records": [
        {
            "uuid": "fake-uuid-1",
            "name": "node_mgmt1",
            "location": {
                "port": {
                    "name": "e0a"
                }
            },
            "service_policy": {
                "name": "default-management"
            },
        },
        {
            "uuid": "fake-uuid-2",
            "name": "cluster_mgmt",
            "location": {
                "port": {
                    "name": "e0a"
                }
            },
            "service_policy": {
                "name": "default-management"
            },
        }
    ],
    "num_records": 2,
}

FAKE_CIFS_LOCAL_USER = {
    'records': [
        {
            'sid': 'S-1-5-21-256008430-3394229847-3930036330-1001'
        }
    ]
}

FAKE_SERVER_SWITCH_NAME = 'fake_ss_name'
FAKE_SUBTYPE = 'fake_subtype'
FAKE_DNS_CONFIG = {
    'dns-state': 'true',
    'domains': ['fake_domain'],
    'dns-ips': ['fake_ip']
}

FAKE_VOLUME_MANAGE = {
    'records': [
        {
            'name': VOLUME_NAMES[0],
            'aggregates': [
                {
                    'name': SHARE_AGGREGATE_NAME
                }
            ],
            'nas': {
                'path': VOLUME_JUNCTION_PATH
            },
            'style': 'flex',
            'type': 'fake_type',
            'svm': {
                'name': VSERVER_NAME
            },
            'qos': {
                'policy': {
                    'name': QOS_POLICY_GROUP_NAME
                }
            },
            'space': {
                'size': SHARE_SIZE
            }
        }
    ],
    'num_records': 1
}

FAKE_PORTS = [
    {'speed': ''},
    {'speed': '4'},
    {'speed': 'auto'},
    {'speed': 'undef'},
    {'speed': 'fake_speed'}
    ]

FAKE_ROOT_AGGREGATES_RESPONSE = {
    "records": [
        {
            "aggregate": SHARE_AGGREGATE_NAME
        }
    ]
}

FAKE_GET_VOLUME = {
    "records": [
        {
            "uuid": FAKE_UUID,
            "name": "share_6cb5b3f4_35d0_40b8_a106_d35262ac17c7",
            "size": 1024**3,
        }
    ],
}
