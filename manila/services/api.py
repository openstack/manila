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

from webob import exc

from manila.db import base
from manila.share import rpcapi as share_rpcapi

CONF = cfg.CONF


class API(base.Base):
    """API for handling service actions."""

    def __init__(self):
        super(API, self).__init__()
        self.share_rpcapi = share_rpcapi.ShareAPI()

    def ensure_shares(self, context, service, host):
        """Start the ensure shares in a given host."""

        if service['state'] != "up":
            raise exc.HTTPConflict(
                "The service must have its state set to 'up' prior to running "
                "ensure shares.")

        self.share_rpcapi.ensure_driver_resources(context, host)
