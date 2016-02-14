# Copyright 2014 Mirantis Inc.
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

import re

from oslo_log import log

from manila.i18n import _LE
from manila import utils

LOG = log.getLogger(__name__)


class OVSBridge(object):
    def __init__(self, br_name):
        self.br_name = br_name
        self.re_id = self.re_compile_id()

    def re_compile_id(self):
        external = 'external_ids\s*'
        mac = 'attached-mac="(?P<vif_mac>([a-fA-F\d]{2}:){5}([a-fA-F\d]{2}))"'
        iface = 'iface-id="(?P<vif_id>[^"]+)"'
        name = 'name\s*:\s"(?P<port_name>[^"]*)"'
        port = 'ofport\s*:\s(?P<ofport>-?\d+)'
        _re = ('%(external)s:\s{ ( %(mac)s,? | %(iface)s,? | . )* }'
               ' \s+ %(name)s \s+ %(port)s' % {'external': external,
                                               'mac': mac,
                                               'iface': iface, 'name': name,
                                               'port': port})
        return re.compile(_re, re.M | re.X)

    def run_vsctl(self, args):
        full_args = ["ovs-vsctl", "--timeout=2"] + args
        try:
            return utils.execute(*full_args, run_as_root=True)
        except Exception as e:
            LOG.error(_LE("Unable to execute %(cmd)s. Exception: "
                          "%(exception)s"),
                      {'cmd': full_args, 'exception': e})

    def reset_bridge(self):
        self.run_vsctl(["--", "--if-exists", "del-br", self.br_name])
        self.run_vsctl(["add-br", self.br_name])

    def delete_port(self, port_name):
        self.run_vsctl(["--", "--if-exists", "del-port", self.br_name,
                        port_name])
