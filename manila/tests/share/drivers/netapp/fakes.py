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


from manila.share import configuration as conf
from manila.share import driver as manila_opts
from manila.share.drivers.netapp import options as na_opts


def create_configuration():
    config = conf.Configuration(None)
    config.append_config_values(manila_opts.share_opts)
    config.append_config_values(na_opts.netapp_connection_opts)
    config.append_config_values(na_opts.netapp_transport_opts)
    config.append_config_values(na_opts.netapp_basicauth_opts)
    config.append_config_values(na_opts.netapp_provisioning_opts)
    return config


def create_configuration_cmode():
    config = create_configuration()
    config.append_config_values(na_opts.netapp_support_opts)
    return config
