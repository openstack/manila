# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
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

from oslo_log import log
from oslo_service import loopingcall

from manila import exception
from manila.i18n import _

LOG = log.getLogger(__name__)


class TaskHelper(object):

    # Task States
    TASK_DONE = "STATE_FINISHED"
    TASK_ACTIVE = "STATE_RUNNING"
    TASK_FAILED = "STATE_FAILED"

    def validate_be_task_resp(self, be_task_resp):
        if 'id' not in be_task_resp:
            msg = _("Did not receive valid id parameter "
                    "in be task response: %(response)s") % {
                'response': be_task_resp}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    def _extract_task_id_from_header(self, response):
        # Extract and return task id from response header
        taskUri = response['Task_uri']
        path_parts = taskUri.split('/')
        task_id = path_parts[-1]
        return task_id

    def _check_task_completion_status(
            self, final_task_status, operation_details):
        self.validate_be_task_resp(final_task_status)

        if final_task_status['status'] != self.TASK_DONE:
            msg = _("%(operation_details)s task "
                    "stopped before it was done. task-status="
                    "%(status)s.") % {'operation_details': operation_details,
                                      'status': final_task_status['status']}
            raise exception.HPEAlletraB10000DriverException(reason=msg)


class TaskWaiter(object):
    """TaskWaiter waits for task to be not active and returns status."""

    def __init__(self, client, task_id, interval=1, initial_delay=0):
        self.be_client = client
        self.task_id = task_id
        self.interval = interval
        self.initial_delay = initial_delay

    def _wait_for_task(self):
        be_header_resp, be_task_resp = self.be_client.get(
            '/tasks/%s' % self.task_id)

        if be_task_resp is None:
            msg = _("Received None response for task %(task_id)s") % {
                'task_id': self.task_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        taskhelper = TaskHelper()
        taskhelper.validate_be_task_resp(be_task_resp)

        LOG.debug("Alletra Task id %(id)s status = %(status)s",
                  {'id': self.task_id,
                   'status': be_task_resp['status']})
        if be_task_resp['status'] != TaskHelper.TASK_ACTIVE:
            raise loopingcall.LoopingCallDone(be_task_resp)

    def wait_for_task(self):
        timer = loopingcall.FixedIntervalLoopingCall(self._wait_for_task)
        return timer.start(interval=self.interval,
                           initial_delay=self.initial_delay).wait()
