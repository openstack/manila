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

from unittest import mock

import ddt
from oslo_service import loopingcall

from manila import exception
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import helpers
from manila import test


@ddt.ddt
class TaskHelperTestCase(test.TestCase):
    """Test case for TaskHelper class."""

    def setUp(self):
        """Test Setup"""
        super(TaskHelperTestCase, self).setUp()
        self.task_helper = helpers.TaskHelper()

    def test_validate_be_task_resp_success(self):
        """Test successful validation of backend task response."""
        be_task_resp = {'id': 'task123', 'status': 'STATE_RUNNING'}
        # Should not raise exception
        self.task_helper.validate_be_task_resp(be_task_resp)

    def test_validate_be_task_resp_missing_id(self):
        """Test validation fails when 'id' key is missing."""
        be_task_resp = {'status': 'STATE_RUNNING'}
        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.task_helper.validate_be_task_resp,
                          be_task_resp)

    def test_extract_task_id_from_header(self):
        """Test extracting task ID from response header."""
        response = {
            'Task_uri': '/api/v3/tasks/06e45f0a78afaa2b9e5188a49f70d517'}
        task_id = self.task_helper._extract_task_id_from_header(response)
        self.assertEqual(task_id, '06e45f0a78afaa2b9e5188a49f70d517')

    def test_extract_task_id_from_header_different_path(self):
        """Test extracting task ID from different Task_uri path."""
        response = {'Task_uri': '/tasks/task456'}
        task_id = self.task_helper._extract_task_id_from_header(response)
        self.assertEqual(task_id, 'task456')

    def test_check_task_completion_status_success(self):
        """Test successful task completion status check."""
        final_task_status = {
            'id': 'task123',
            'status': helpers.TaskHelper.TASK_DONE}
        operation_details = "Create fileshare"
        # Should not raise exception
        self.task_helper._check_task_completion_status(
            final_task_status, operation_details)

    def test_check_task_completion_status_failed(self):
        """Test task completion status check when task failed."""
        final_task_status = {'id': 'task123', 'status': 'STATE_FAILED'}
        operation_details = "Create fileshare"
        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.task_helper._check_task_completion_status,
                          final_task_status, operation_details)

    def test_check_task_completion_status_missing_id(self):
        """Test task completion status check with invalid response."""
        final_task_status = {
            'status': helpers.TaskHelper.TASK_DONE}  # Missing 'id'
        operation_details = "Create fileshare"
        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.task_helper._check_task_completion_status,
                          final_task_status, operation_details)


@ddt.ddt
class TaskWaiterTestCase(test.TestCase):
    """Test case for TaskWaiter class."""

    def setUp(self):
        """Test Setup"""
        super(TaskWaiterTestCase, self).setUp()
        self.mock_client = mock.Mock()
        self.task_id = '06e45f0a78afaa2b9e5188a49f70d517'
        self.task_waiter = helpers.TaskWaiter(self.mock_client, self.task_id)

    def test_init_default_values(self):
        """Test TaskWaiter initialization with default values."""
        waiter = helpers.TaskWaiter(self.mock_client, self.task_id)
        self.assertEqual(waiter.be_client, self.mock_client)
        self.assertEqual(waiter.task_id, self.task_id)
        self.assertEqual(waiter.interval, 1)
        self.assertEqual(waiter.initial_delay, 0)

    def test_init_custom_values(self):
        """Test TaskWaiter initialization with custom values."""
        waiter = helpers.TaskWaiter(
            self.mock_client,
            self.task_id,
            interval=2,
            initial_delay=5)
        self.assertEqual(waiter.be_client, self.mock_client)
        self.assertEqual(waiter.task_id, self.task_id)
        self.assertEqual(waiter.interval, 2)
        self.assertEqual(waiter.initial_delay, 5)

    @mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall')
    def test_wait_for_task_success(self, mock_looping_call):
        """Test successful wait for task completion."""
        # Mock the looping call
        mock_timer = mock.Mock()
        mock_looping_call.return_value = mock_timer
        mock_timer.start.return_value.wait.return_value = {
            'status': helpers.TaskHelper.TASK_DONE}

        result = self.task_waiter.wait_for_task()
        self.assertEqual(result, {'status': helpers.TaskHelper.TASK_DONE})

        # Verify the timer was started with correct parameters
        mock_timer.start.assert_called_once_with(interval=1, initial_delay=0)

    @mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall')
    def test_wait_for_task_custom_timing(self, mock_looping_call):
        """Test wait for task with custom timing parameters."""
        waiter = helpers.TaskWaiter(
            self.mock_client,
            self.task_id,
            interval=3,
            initial_delay=2)
        mock_timer = mock.Mock()
        mock_looping_call.return_value = mock_timer
        mock_timer.start.return_value.wait.return_value = {
            'status': helpers.TaskHelper.TASK_DONE}

        result = waiter.wait_for_task()
        self.assertEqual(result, {'status': helpers.TaskHelper.TASK_DONE})

        # Verify the timer was started with custom parameters
        mock_timer.start.assert_called_once_with(interval=3, initial_delay=2)

    def test_wait_for_task_active_status(self):
        """Test _wait_for_task when task is still active."""
        # Mock client response for active task
        be_header_resp = {}
        be_task_resp = {
            'id': self.task_id,
            'status': helpers.TaskHelper.TASK_ACTIVE}
        self.mock_client.get.return_value = (be_header_resp, be_task_resp)

        # Should NOT raise exception when task is active - polling continues
        self.task_waiter._wait_for_task()

        # Verify client was called correctly
        self.mock_client.get.assert_called_once_with(
            '/tasks/%s' % self.task_id)

    def test_wait_for_task_active_string_comparison(self):
        """Test _wait_for_task correctly compares string status values."""
        # Mock client response with same string value as constant
        be_header_resp = {}
        be_task_resp = {
            'id': self.task_id,
            'status': "STATE_RUNNING"}  # String literal, not constant
        self.mock_client.get.return_value = (be_header_resp, be_task_resp)

        # Should work with string comparison (not identity check)
        self.task_waiter._wait_for_task()

        # Verify client was called correctly
        self.mock_client.get.assert_called_once_with(
            '/tasks/%s' % self.task_id)

    def test_wait_for_task_completed_status(self):
        """Test _wait_for_task when task is completed."""
        # Mock client response for completed task
        be_header_resp = {}
        be_task_resp = {
            'id': self.task_id,
            'status': helpers.TaskHelper.TASK_DONE}
        self.mock_client.get.return_value = (be_header_resp, be_task_resp)

        self.assertRaises(loopingcall.LoopingCallDone,
                          self.task_waiter._wait_for_task)

        # Verify client was called correctly
        self.mock_client.get.assert_called_once_with(
            '/tasks/%s' % self.task_id)

    def test_wait_for_task_invalid_response(self):
        """Test _wait_for_task with invalid backend response."""
        # Mock client response with missing 'id'
        be_header_resp = {}
        be_task_resp = {'status': helpers.TaskHelper.TASK_DONE}  # Missing 'id'
        self.mock_client.get.return_value = (be_header_resp, be_task_resp)

        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.task_waiter._wait_for_task)

    def test_wait_for_task_none_response(self):
        """Test _wait_for_task when client returns None response."""
        # Mock client response as None
        be_header_resp = {}
        be_task_resp = None
        self.mock_client.get.return_value = (be_header_resp, be_task_resp)

        self.assertRaises(exception.HPEAlletraB10000DriverException,
                          self.task_waiter._wait_for_task)

        # Verify client was called correctly
        self.mock_client.get.assert_called_once_with(
            '/tasks/%s' % self.task_id)

    def test_validate_be_task_resp_missing_id_with_response(self):
        """Test validation error includes response for debugging."""
        be_task_resp = {'status': 'STATE_RUNNING', 'error': 'test error'}

        # Mock client response with missing 'id'
        be_header_resp = {}
        self.mock_client.get.return_value = (be_header_resp, be_task_resp)

        exc = self.assertRaises(exception.HPEAlletraB10000DriverException,
                                self.task_waiter._wait_for_task)
        self.assertIn('id parameter', str(exc))
