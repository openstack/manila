# Copyright (c) 2015 Huawei Technologies Co., Ltd.
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

from oslo_utils import strutils


class SmartX(object):
    def get_smartx_extra_specs_opts(self, opts):
        opts = self.get_capabilities_opts(opts, 'dedupe')
        opts = self.get_capabilities_opts(opts, 'compression')
        opts = self.get_smartprovisioning_opts(opts)
        return opts

    def get_capabilities_opts(self, opts, key):
        if strutils.bool_from_string(opts[key]):
            opts[key] = True
        else:
            opts[key] = False

        return opts

    def get_smartprovisioning_opts(self, opts):
        if strutils.bool_from_string(opts['thin_provisioning']):
            opts['LUNType'] = 1
        else:
            opts['LUNType'] = 0

        return opts
