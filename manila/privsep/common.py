# Copyright 2021 Red Hat, Inc
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

from manila import exception
from manila import utils as manila_utils
from oslo_log import log

LOG = log.getLogger(__name__)


def execute_with_retries(action, action_args, max_retries):

    @manila_utils.retry(
        retry_param=exception.ProcessExecutionError, backoff_rate=2,
        retries=max_retries)
    def execute():
        try:
            action(*action_args)
            return True
        except exception.ProcessExecutionError:
            LOG.exception("Recovering from a failed execute.")
            raise

    try:
        execute()
    except exception.ProcessExecutionError:
        LOG.exception("Failed to run command. Tries exhausted.")
        raise
