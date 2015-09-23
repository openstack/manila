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
        config.register_opt_group(
            conf, config_share.service_available_group,
            config_share.ServiceAvailableGroup)
        config.register_opt_group(conf, config_share.share_group,
                                  config_share.ShareGroup)

        # NOTE(vponomaryov): set opt 'capability_snapshot_support' by
        # default equal to opt 'run_snapshot_tests'.
        if conf.share.capability_snapshot_support is None:
            conf.set_default(
                "capability_snapshot_support",
                conf.share.run_snapshot_tests,
                group="share",
            )

    def get_opt_lists(self):
        return [(config_share.share_group.name, config_share.ShareGroup)]
