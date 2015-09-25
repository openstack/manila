# Copyright (c) 2015 Mirantis, Inc.
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

from oslo_config import cfg
from zaqarclient.queues import client as zaqar

zaqar_notification_opts = [
    cfg.StrOpt(
        "zaqar_username",
        help="Username that should be used for init of zaqar client.",
    ),
    cfg.StrOpt(
        "zaqar_password",
        secret=True,
        help="Password for user specified in opt 'zaqar_username'.",
    ),
    cfg.StrOpt(
        "zaqar_project_name",
        help=("Project/Tenant name that is owns user specified "
              "in opt 'zaqar_username'."),
    ),
    cfg.StrOpt(
        "zaqar_auth_url",
        default="http://127.0.0.1:35357/v2.0/",
        help="Auth url to be used by Zaqar client.",
    ),
    cfg.StrOpt(
        "zaqar_region_name",
        help="Name of the region that should be used. Optional.",
    ),
    cfg.StrOpt(
        "zaqar_service_type",
        default="messaging",
        help="Service type for Zaqar. Optional.",
    ),
    cfg.StrOpt(
        "zaqar_endpoint_type",
        default="publicURL",
        help="Type of endpoint to be used for init of Zaqar client. Optional.",
    ),
    cfg.FloatOpt(
        "zaqar_api_version",
        default=1.1,
        help="Version of Zaqar API to use. Optional.",
    ),
    cfg.ListOpt(
        "zaqar_queues",
        default=["manila_notification_qeueue"],
        help=("List of queues names to be used for sending Manila "
              "notifications. Optional."),
    ),
]

CONF = cfg.CONF
CONF.register_opts(zaqar_notification_opts, group='zaqar')

ZAQARCLIENT = zaqar.Client(
    version=CONF.zaqar.zaqar_api_version,
    conf={
        "auth_opts": {
            "backend": "keystone",
            "options": {
                "os_username": CONF.zaqar.zaqar_username,
                "os_password": CONF.zaqar.zaqar_password,
                "os_project_name": CONF.zaqar.zaqar_project_name,
                "os_auth_url": CONF.zaqar.zaqar_auth_url,
                "os_region_name": CONF.zaqar.zaqar_region_name,
                "os_service_type": CONF.zaqar.zaqar_service_type,
                "os_endpoint_type": CONF.zaqar.zaqar_endpoint_type,
                "insecure": True,
            },
        },
    },
)
