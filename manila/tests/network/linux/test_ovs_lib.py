# Copyright 2014 Mirantis Inc.
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

from manila.network.linux import ovs_lib
from manila import test


class OVS_Lib_Test(test.TestCase):
    """A test suite to exercise the OVS libraries."""

    def setUp(self):
        super(OVS_Lib_Test, self).setUp()
        self.BR_NAME = "br-int"
        self.TO = "--timeout=2"

        self.br = ovs_lib.OVSBridge(self.BR_NAME)
        self.execute_p = mock.patch('manila.utils.execute')
        self.execute = self.execute_p.start()

    def tearDown(self):
        self.execute_p.stop()
        super(OVS_Lib_Test, self).tearDown()

    def test_reset_bridge(self):
        self.br.reset_bridge()
        self.execute.assert_has_calls([mock.call("ovs-vsctl", self.TO, "--",
                                                 "--if-exists", "del-br",
                                                 self.BR_NAME,
                                                 run_as_root=True),
                                       mock.call("ovs-vsctl", self.TO,
                                                 "add-br",
                                                 self.BR_NAME,
                                                 run_as_root=True)])

    def test_delete_port(self):
        pname = "tap5"
        self.br.delete_port(pname)
        self.execute.assert_called_once_with("ovs-vsctl", self.TO, "--",
                                             "--if-exists", "del-port",
                                             self.BR_NAME, pname,
                                             run_as_root=True)

    def test_port_id_regex(self):
        result = ('external_ids        : {attached-mac="fa:16:3e:23:5b:f2",'
                  ' iface-id="5c1321a7-c73f-4a77-95e6-9f86402e5c8f",'
                  ' iface-status=active}\nname                :'
                  ' "dhc5c1321a7-c7"\nofport              : 2\n')
        match = self.br.re_id.search(result)
        vif_mac = match.group('vif_mac')
        vif_id = match.group('vif_id')
        port_name = match.group('port_name')
        ofport = int(match.group('ofport'))
        self.assertEqual('fa:16:3e:23:5b:f2', vif_mac)
        self.assertEqual('5c1321a7-c73f-4a77-95e6-9f86402e5c8f', vif_id)
        self.assertEqual('dhc5c1321a7-c7', port_name)
        self.assertEqual(2, ofport)
