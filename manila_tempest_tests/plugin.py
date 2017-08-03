# Copyright 2015 Deutsche Telekom AG
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


import os

from tempest import config
from tempest.test_discover import plugins

from manila_tempest_tests import config as config_share


class ManilaTempestPlugin(plugins.TempestPlugin):
    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "manila_tempest_tests/tests"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        conf.register_opt(config_share.service_option,
                          group='service_available')
        conf.register_group(config_share.share_group)
        conf.register_opts(config_share.ShareGroup, group='share')

        # NOTE(vponomaryov): Set options 'capability_snapshot_support' and
        # 'capability_create_share_from_snapshot_support' to opt
        # 'run_snapshot_tests' if not configured.
        if conf.share.capability_snapshot_support is None:
            conf.set_default(
                "capability_snapshot_support",
                conf.share.run_snapshot_tests,
                group="share",
            )
        if conf.share.capability_create_share_from_snapshot_support is None:
            conf.set_default(
                "capability_create_share_from_snapshot_support",
                conf.share.run_snapshot_tests,
                group="share",
            )

    def get_opt_lists(self):
        return [(config_share.share_group.name, config_share.ShareGroup),
                ('service_available', [config_share.service_option])]

    def get_service_clients(self):
        shares_config = config.service_client_config('share')
        v1_params = {
            'name': 'share_v1',
            'service_version': 'share.v1',
            'module_path': 'manila_tempest_tests.services.share.json',
            'client_names': ['SharesClient'],
        }
        v2_params = {
            'name': 'share_v2',
            'service_version': 'share.v2',
            'module_path': 'manila_tempest_tests.services.share.v2',
            'client_names': ['SharesV2Client'],
        }
        v1_params.update(shares_config)
        v2_params.update(shares_config)
        return [v1_params, v2_params]
