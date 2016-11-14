# Copyright (c) 2014 EMC Corporation.
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

from lxml import etree
import six


class XMLAPIParser(object):
    def __init__(self):
        # The following Boolean acts as the flag for the common sub-element.
        # For instance:
        #     <CifsServers>
        #         <li> server_1 </li>
        #     </CifsServers>
        #     <Alias>
        #         <li> interface_1 </li>
        #     </Alias>
        self.is_QueryStatus = False
        self.is_CifsServers = False
        self.is_Aliases = False
        self.is_MoverStatus = False
        self.is_TaskResponse = False
        self.is_Vdm = False
        self.is_Interfaces = False

        self.elt = {}

    def _remove_ns(self, tag):
        i = tag.find('}')
        if i >= 0:
            tag = tag[i + 1:]
        return tag

    def parse(self, xml):
        result = {
            'type': None,
            'taskId': None,
            'maxSeverity': None,
            'objects': [],
            'problems': [],
        }

        events = ("start", "end")

        context = etree.iterparse(six.BytesIO(xml.encode('utf-8')),
                                  events=events)
        for action, elem in context:
            self.tag = self._remove_ns(elem.tag)

            func = self._get_func(action, self.tag)
            if func in vars(XMLAPIParser):
                if action == 'start':
                    eval('self.' + func)(elem, result)
                elif action == 'end':
                    eval('self.' + func)()

        return result

    def _get_func(self, action, tag):
        if tag == 'W2KServerData':
            return action + '_' + 'w2k_server_data'

        temp_list = re.sub(r"([A-Z])", r" \1", tag).split()
        if temp_list:
            func_name = action + '_' + '_'.join(temp_list)
        else:
            func_name = action + '_' + tag
        return func_name.lower()

    def _copy_property(self, source, target, property, list_property=None):
        for key in property:
            if key in source:
                target[key] = source[key]

        if list_property:
            for key in list_property:
                if key in source:
                    target[key] = source[key].split()

    def _append_elm_property(self, elm, result, property, identifier):
        for obj in result['objects']:
            if (identifier in obj and identifier in elm.attrib and
                    elm.attrib[identifier] == obj[identifier]):
                for key, value in elm.attrib.items():
                    if key in property:
                        obj[key] = value

    def _append_element(self, elm, result, property, list_property,
                        identifier):
        sub_elm = {}
        self._copy_property(elm.attrib, sub_elm, property, list_property)

        for obj in result['objects']:
            if (identifier in obj and identifier in elm.attrib and
                    elm.attrib[identifier] == obj[identifier]):
                if self.tag in obj:
                    obj[self.tag].append(sub_elm)
                else:
                    obj[self.tag] = [sub_elm]

    def start_task_response(self, elm, result):
        self.is_TaskResponse = True
        result['type'] = 'TaskResponse'
        self._copy_property(elm.attrib, result, ['taskId'])

    def end_task_response(self):
        self.is_TaskResponse = False

    def start_fault(self, elm, result):
        result['type'] = 'Fault'

    def start_status(self, elm, result):
        if self.is_TaskResponse:
            result['maxSeverity'] = elm.attrib['maxSeverity']
        elif self.is_MoverStatus or self.is_Vdm:
            self.elt['maxSeverity'] = elm.attrib['maxSeverity']

    def start_query_status(self, elm, result):
        self.is_QueryStatus = True
        result['type'] = 'QueryStatus'
        self._copy_property(elm.attrib, result, ['maxSeverity'])

    def end_query_status(self):
        self.is_QueryStatus = False

    def start_problem(self, elm, result):
        self.elt = {}
        properties = ('message', 'messageCode')

        self._copy_property(elm.attrib, self.elt, properties)
        result['problems'].append(self.elt)

    def start_description(self, elm, result):
        self.elt['Description'] = elm.text

    def start_action(self, elm, result):
        self.elt['Action'] = elm.text

    def start_diagnostics(self, elm, result):
        self.elt['Diagnostics'] = elm.text

    def start_file_system(self, elm, result):
        self.elt = {}
        property = (
            'fileSystem',
            'name',
            'type',
            'storages',
            'volume',
            'dataServicePolicies',
            'internalUse',
        )
        list_property = ('storagePools',)

        self._copy_property(elm.attrib, self.elt, property, list_property)
        result['objects'].append(self.elt)

    def start_file_system_capacity_info(self, elm, result):
        property = ('volumeSize',)

        identifier = 'fileSystem'

        self._append_elm_property(elm, result, property, identifier)

    def start_storage_pool(self, elm, result):
        self.elt = {}
        property = ('name', 'autoSize', 'usedSize', 'diskType', 'pool',
                    'dataServicePolicies', 'virtualProvisioning')
        list_property = ('movers',)

        self._copy_property(elm.attrib, self.elt, property, list_property)
        result['objects'].append(self.elt)

    def start_system_storage_pool_data(self, elm, result):
        property = ('greedy', 'isBackendPool')

        self._copy_property(elm.attrib, self.elt, property)

    def start_mover(self, elm, result):
        self.elt = {}
        property = ('name', 'host', 'mover', 'role')
        list_property = ('ntpServers', 'standbyFors', 'standbys')

        self._copy_property(elm.attrib, self.elt, property, list_property)
        result['objects'].append(self.elt)

    def start_mover_status(self, elm, result):
        self.is_MoverStatus = True

        property = ('version', 'csTime', 'clock', 'timezone', 'uptime')

        identifier = 'mover'

        self._append_elm_property(elm, result, property, identifier)

    def end_mover_status(self):
        self.is_MoverStatus = False

    def start_mover_dns_domain(self, elm, result):
        property = ('name', 'protocol')
        list_property = ('servers',)

        identifier = 'mover'

        self._append_element(elm, result, property, list_property, identifier)

    def start_mover_interface(self, elm, result):
        property = (
            'name',
            'device',
            'up',
            'ipVersion',
            'netMask',
            'ipAddress',
            'vlanid',
        )

        identifier = 'mover'

        self._append_element(elm, result, property, None, identifier)

    def start_logical_network_device(self, elm, result):
        property = ('name', 'type', 'speed')
        list_property = ('interfaces',)
        identifier = 'mover'

        self._append_element(elm, result, property, list_property, identifier)

    def start_vdm(self, elm, result):
        self.is_Vdm = True

        self.elt = {}
        property = ('name', 'state', 'mover', 'vdm')

        self._copy_property(elm.attrib, self.elt, property)
        result['objects'].append(self.elt)

    def end_vdm(self):
        self.is_Vdm = False

    def start_interfaces(self, elm, result):
        self.is_Interfaces = True
        self.elt['Interfaces'] = []

    def end_interfaces(self):
        self.is_Interfaces = False

    def start_li(self, elm, result):
        if self.is_CifsServers:
            self.elt['CifsServers'].append(elm.text)
        elif self.is_Aliases:
            self.elt['Aliases'].append(elm.text)
        elif self.is_Interfaces:
            self.elt['Interfaces'].append(elm.text)

    def start_cifs_server(self, elm, result):
        self.elt = {}
        property = ('type', 'localUsers', 'name', 'mover', 'moverIdIsVdm')

        list_property = ('interfaces',)

        self._copy_property(elm.attrib, self.elt, property, list_property)
        result['objects'].append(self.elt)

    def start_aliases(self, elm, result):
        self.is_Aliases = True
        self.elt['Aliases'] = []

    def end_aliases(self):
        self.is_Aliases = False

    def start_w2k_server_data(self, elm, result):
        property = ('domain', 'compName', 'domainJoined')

        self._copy_property(elm.attrib, self.elt, property)

    def start_cifs_share(self, elm, result):
        self.elt = {}
        property = ('path', 'fileSystem', 'name', 'mover', 'moverIdIsVdm')

        self._copy_property(elm.attrib, self.elt, property)
        result['objects'].append(self.elt)

    def start_cifs_servers(self, elm, result):
        self.is_CifsServers = True
        self.elt['CifsServers'] = []

    def end_cifs_servers(self):
        self.is_CifsServers = False

    def start_checkpoint(self, elm, result):
        self.elt = {}
        property = ('checkpointOf', 'name', 'checkpoint', 'state')

        self._copy_property(elm.attrib, self.elt, property)
        result['objects'].append(self.elt)

    def start_mount(self, elm, result):
        self.elt = {}
        property = ('fileSystem', 'path', 'mover', 'moverIdIsVdm')

        self._copy_property(elm.attrib, self.elt, property)
        result['objects'].append(self.elt)
