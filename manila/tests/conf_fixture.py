# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

from oslo_policy import opts
from oslo_service import wsgi

from manila.common import config

CONF = config.CONF


def set_defaults(conf):
    _safe_set_of_opts(conf, 'verbose', True)
    _safe_set_of_opts(conf, 'state_path', os.path.abspath(
        os.path.join(os.path.dirname(__file__),
                     '..',
                     '..')))
    _safe_set_of_opts(conf, 'connection', "sqlite://", group='database')
    _safe_set_of_opts(conf, 'sqlite_synchronous', False)
    _POLICY_PATH = os.path.abspath(os.path.join(CONF.state_path,
                                                'manila/tests/policy.json'))
    opts.set_defaults(conf, policy_file=_POLICY_PATH)
    _safe_set_of_opts(conf, 'share_export_ip', '0.0.0.0')
    _safe_set_of_opts(conf, 'service_instance_user', 'fake_user')
    _API_PASTE_PATH = os.path.abspath(os.path.join(CONF.state_path,
                                                   'etc/manila/api-paste.ini'))
    wsgi.register_opts(conf)
    _safe_set_of_opts(conf, 'api_paste_config', _API_PASTE_PATH)
    _safe_set_of_opts(conf, 'share_driver',
                      'manila.tests.fake_driver.FakeShareDriver')
    _safe_set_of_opts(conf, 'auth_strategy', 'noauth')

    _safe_set_of_opts(conf, 'zfs_share_export_ip', '1.1.1.1')
    _safe_set_of_opts(conf, 'zfs_service_ip', '2.2.2.2')
    _safe_set_of_opts(conf, 'zfs_zpool_list', ['foo', 'bar'])
    _safe_set_of_opts(conf, 'zfs_share_helpers', 'NFS=foo.bar.Helper')
    _safe_set_of_opts(conf, 'zfs_replica_snapshot_prefix', 'foo_prefix_')

    _safe_set_of_opts(conf, 'hitachi_hsp_host', '172.24.47.190')
    _safe_set_of_opts(conf, 'hitachi_hsp_username', 'hsp_user')
    _safe_set_of_opts(conf, 'hitachi_hsp_password', 'hsp_password')

    _safe_set_of_opts(conf, 'qnap_management_url', 'http://1.2.3.4:8080')
    _safe_set_of_opts(conf, 'qnap_share_ip', '1.2.3.4')
    _safe_set_of_opts(conf, 'qnap_nas_login', 'admin')
    _safe_set_of_opts(conf, 'qnap_nas_password', 'qnapadmin')
    _safe_set_of_opts(conf, 'qnap_poolname', 'Storage Pool 1')

    _safe_set_of_opts(conf, 'unity_server_meta_pool', 'nas_server_pool')


def _safe_set_of_opts(conf, *args, **kwargs):
    try:
        conf.set_default(*args, **kwargs)
    except config.cfg.NoSuchOptError:
        # Assumed that opt is not imported and not used
        pass
