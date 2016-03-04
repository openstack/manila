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

from lxml import etree
import mock
from six.moves import urllib

from manila.share.drivers.netapp.dataontap.client import api


CONNECTION_INFO = {
    'hostname': 'hostname',
    'transport_type': 'https',
    'port': 443,
    'username': 'admin',
    'password': 'passw0rd'
}

CLUSTER_NAME = 'fake_cluster'
REMOTE_CLUSTER_NAME = 'fake_cluster_2'
CLUSTER_ADDRESS_1 = 'fake_cluster_address'
CLUSTER_ADDRESS_2 = 'fake_cluster_address_2'
VERSION = 'NetApp Release 8.2.1 Cluster-Mode: Fri Mar 21 14:25:07 PDT 2014'
NODE_NAME = 'fake_node'
VSERVER_NAME = 'fake_vserver'
VSERVER_NAME_2 = 'fake_vserver_2'
ADMIN_VSERVER_NAME = 'fake_admin_vserver'
NODE_VSERVER_NAME = 'fake_node_vserver'
ROOT_VOLUME_AGGREGATE_NAME = 'fake_root_aggr'
ROOT_VOLUME_NAME = 'fake_root_volume'
SHARE_AGGREGATE_NAME = 'fake_aggr1'
SHARE_AGGREGATE_NAMES = ('fake_aggr1', 'fake_aggr2')
SHARE_AGGREGATE_RAID_TYPES = ('raid4', 'raid_dp')
SHARE_AGGREGATE_DISK_TYPE = 'FCAL'
SHARE_NAME = 'fake_share'
SHARE_SIZE = '1000000000'
SHARE_NAME_2 = 'fake_share_2'
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

USER_NAME = 'fake_user'

PORT = 'e0a'
VLAN = '1001'
VLAN_PORT = 'e0a-1001'
IP_ADDRESS = '10.10.10.10'
NETMASK = '255.255.255.0'
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

NO_RECORDS_RESPONSE = etree.XML("""
  <results status="passed">
    <num-records>0</num-records>
  </results>
""")

PASSED_RESPONSE = etree.XML("""
  <results status="passed" />
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
    'domain': 'fake_domain',
    'dns_ip': 'fake_dns_ip',
}

LDAP_SECURITY_SERVICE = {
    'type': 'ldap',
    'password': 'fake_password',
    'server': 'fake_server',
    'id': 'fake_id',
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
        <aggregate-name>%(aggr2)s</aggregate-name>
      </aggr-attributes>
    </attributes-list>
    <num-records>2</num-records>
  </results>
""" % {
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

SNAPSHOT_GET_ITER_NOT_BUSY_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
        <busy>false</busy>
        <name>%(snap)s</name>
        <volume>%(volume)s</volume>
        <vserver>%(vserver)s</vserver>
      </snapshot-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % {'snap': SNAPSHOT_NAME, 'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

SNAPSHOT_GET_ITER_BUSY_RESPONSE = etree.XML("""
  <results status="passed">
    <attributes-list>
      <snapshot-info>
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
""" % {'snap': SNAPSHOT_NAME, 'volume': SHARE_NAME, 'vserver': VSERVER_NAME})

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
          <effective-disk-type>%s</effective-disk-type>
        </disk-raid-info>
      </storage-disk-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""" % SHARE_AGGREGATE_DISK_TYPE)

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
        <schedule>daily</schedule>
        <source-vserver>fake_source_vserver</source-vserver>
        <source-volume>fake_source_volume</source-volume>
      </snapmirror-info>
    </attributes-list>
    <num-records>1</num-records>
  </results>
""")

SNAPMIRROR_INITIALIZE_RESULT = etree.XML("""
  <results status="passed">
    <result-status>succeeded</result-status>
  </results>
""")

FAKE_VOL_XML = """<volume-info xmlns='http://www.netapp.com/filer/admin'>
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

FAKE_HTTP_OPENER = urllib.request.build_opener()
