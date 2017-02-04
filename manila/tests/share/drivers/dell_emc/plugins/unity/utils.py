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

from os import path
import yaml

import mock
from oslo_log import log

LOG = log.getLogger(__name__)

patch_system = mock.patch('storops.UnitySystem')


def load_yaml(file_name):
    yaml_file = '{}/{}'.format(path.dirname(path.abspath(__file__)), file_name)
    with open(yaml_file) as f:
        res = yaml.safe_load(f)
        LOG.debug('Loaded yaml mock objects from %s.', yaml_file)
    return res

patch_find_ports_by_mtu = mock.patch('manila.share.drivers.dell_emc.plugins.'
                                     'unity.utils.find_ports_by_mtu')
