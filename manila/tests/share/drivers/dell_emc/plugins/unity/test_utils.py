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

import ddt
from oslo_utils import units

from manila.share.drivers.dell_emc.plugins.unity import utils
from manila import test


class MockPort(object):
    def __init__(self, sp_id):
        self.sp_id = sp_id

    def get_id(self):
        return self.sp_id


SPA = MockPort('spa')
SPB = MockPort('spb')


class MockPort(object):
    def __init__(self, sp, port_id, mtu):
        self._sp = sp
        self.port_id = port_id
        self.mtu = mtu

    def get_id(self):
        return self.port_id

    @property
    def parent_storage_processor(self):
        return self._sp


SPA_ETH0 = MockPort(SPA, 'spa_eth0', 1500)
SPA_ETH1 = MockPort(SPA, 'spa_eth1', 9000)
SPB_ETH0 = MockPort(SPB, 'spb_eth0', 1500)
SPB_ETH1 = MockPort(SPB, 'spb_eth1', 9000)
SPA_LA1 = MockPort(SPA, 'spa_la_1', 1500)
SPB_LA1 = MockPort(SPB, 'spb_la_1', 1500)


@ddt.ddt
class TestUtils(test.TestCase):
    @ddt.data({'matcher': None,
               'matched': {'pool_1', 'pool_2', 'nas_server_pool'},
               'not_matched': set()},
              {'matcher': ['*'],
               'matched': {'pool_1', 'pool_2', 'nas_server_pool'},
               'not_matched': set()},
              {'matcher': ['pool_*'],
               'matched': {'pool_1', 'pool_2'},
               'not_matched': {'nas_server_pool'}},
              {'matcher': ['*pool'],
               'matched': {'nas_server_pool'},
               'not_matched': {'pool_1', 'pool_2'}},
              {'matcher': ['nas_server_pool'],
               'matched': {'nas_server_pool'},
               'not_matched': {'pool_1', 'pool_2'}},
              {'matcher': ['nas_*', 'pool_*'],
               'matched': {'pool_1', 'pool_2', 'nas_server_pool'},
               'not_matched': set()})
    def test_do_match(self, data):
        full = ['pool_1 ', ' pool_2', ' nas_server_pool ']
        matcher = data['matcher']
        expected_matched = data['matched']
        expected_not_matched = data['not_matched']

        matched, not_matched = utils.do_match(full, matcher)
        self.assertEqual(expected_matched, matched)
        self.assertEqual(expected_not_matched, not_matched)

    @ddt.data({'ports': [SPA_ETH0, SPB_ETH0],
               'ids_conf': None,
               'port_map': {'spa': {'spa_eth0'}, 'spb': {'spb_eth0'}},
               'unmanaged': set()},
              {'ports': [SPA_ETH0, SPB_ETH0],
               'ids_conf': ['   '],
               'port_map': {'spa': {'spa_eth0'}, 'spb': {'spb_eth0'}},
               'unmanaged': set()},
              {'ports': [SPA_ETH0, SPB_ETH0, SPA_ETH1],
               'ids_conf': ['spa*'],
               'port_map': {'spa': {'spa_eth0', 'spa_eth1'}},
               'unmanaged': {'spb_eth0'}},
              )
    @ddt.unpack
    def test_match_ports(self, ports, ids_conf, port_map, unmanaged):
        sp_ports_map, unmanaged_port_ids = utils.match_ports(ports,
                                                             ids_conf)
        self.assertEqual(port_map, sp_ports_map)
        self.assertEqual(unmanaged, unmanaged_port_ids)

    def test_find_ports_by_mtu(self):
        all_ports = [SPA_ETH0, SPB_ETH0, SPA_ETH1, SPB_ETH1, SPA_LA1,
                     SPB_LA1]
        port_ids_conf = '*'
        port_map = utils.find_ports_by_mtu(all_ports, port_ids_conf, 1500)
        self.assertEqual({'spa': {'spa_eth0', 'spa_la_1'},
                          'spb': {'spb_eth0', 'spb_la_1'}},
                         port_map)

    def test_gb_to_byte(self):
        self.assertEqual(3 * units.Gi, utils.gib_to_byte(3))
