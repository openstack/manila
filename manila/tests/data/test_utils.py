# Copyright 2015 Hitachi Data Systems inc.
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

import mock

from manila.data import utils as data_utils
from manila import test
from manila import utils


class CopyClassTestCase(test.TestCase):
    def setUp(self):
        super(CopyClassTestCase, self).setUp()
        src = '/path/fake/src'
        dest = '/path/fake/dst'
        ignore_list = ['item']
        self._copy = data_utils.Copy(src, dest, ignore_list)
        self._copy.total_size = 10000
        self._copy.current_size = 100
        self._copy.current_copy = {'file_path': '/fake/path', 'size': 100}

        self.mock_log = self.mock_object(data_utils, 'LOG')

    def test_get_progress(self):
        expected = {'total_progress': 1,
                    'current_file_path': '/fake/path',
                    'current_file_progress': 100}

        # mocks
        self.mock_object(utils, 'execute',
                         mock.Mock(return_value=("100", "")))

        # run
        out = self._copy.get_progress()

        # asserts
        self.assertEqual(expected, out)

        utils.execute.assert_called_once_with("stat", "-c", "%s", "/fake/path",
                                              run_as_root=True)

    def test_get_progress_current_copy_none(self):
        self._copy.current_copy = None
        expected = {'total_progress': 100}

        # run
        out = self._copy.get_progress()

        # asserts
        self.assertEqual(expected, out)

    def test_get_progress_exception(self):
        expected = {'total_progress': 1,
                    'current_file_path': '/fake/path',
                    'current_file_progress': 0}

        # mocks
        self.mock_object(
            utils, 'execute',
            mock.Mock(side_effect=utils.processutils.ProcessExecutionError()))

        # run
        out = self._copy.get_progress()

        # asserts
        self.assertEqual(expected, out)

        utils.execute.assert_called_once_with("stat", "-c", "%s", "/fake/path",
                                              run_as_root=True)

    def test_cancel(self):
        self._copy.cancelled = False

        # run
        self._copy.cancel()

        # asserts
        self.assertEqual(self._copy.cancelled, True)

        # reset
        self._copy.cancelled = False

    def test_get_total_size(self):
        self._copy.total_size = 0

        values = [("folder1/\nitem/\nfile1\nitem", ""),
                  ("", ""),
                  ("10000", "")]

        def get_output(*args, **kwargs):
            return values.pop(0)

        # mocks
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=get_output))

        # run
        self._copy.get_total_size(self._copy.src)

        # asserts
        self.assertEqual(self._copy.total_size, 10000)

        utils.execute.assert_has_calls([
            mock.call("ls", "-pA1", "--group-directories-first",
                      self._copy.src, run_as_root=True),
            mock.call("ls", "-pA1", "--group-directories-first",
                      os.path.join(self._copy.src, "folder1/"),
                      run_as_root=True),
            mock.call("stat", "-c", "%s",
                      os.path.join(self._copy.src, "file1"), run_as_root=True)
        ])

    def test_get_total_size_cancelled_1(self):
        self._copy.total_size = 0
        self._copy.cancelled = True

        # run
        self._copy.get_total_size(self._copy.src)

        # asserts
        self.assertEqual(self._copy.total_size, 0)

        # reset
        self._copy.total_size = 10000
        self._copy.cancelled = False

    def test_get_total_size_cancelled_2(self):
        self._copy.total_size = 0

        def ls_output(*args, **kwargs):
            self._copy.cancelled = True
            return "folder1/", ""

        # mocks
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=ls_output))

        # run
        self._copy.get_total_size(self._copy.src)

        # asserts
        self.assertEqual(self._copy.total_size, 0)
        utils.execute.assert_called_once_with(
            "ls", "-pA1", "--group-directories-first", self._copy.src,
            run_as_root=True)

        # reset
        self._copy.total_size = 10000
        self._copy.cancelled = False

    def test_copy_data(self):

        values = [("folder1/\nitem/\nfile1\nitem", ""),
                  "",
                  ("", ""),
                  ("10000", ""),
                  ""]

        def get_output(*args, **kwargs):
            return values.pop(0)

        # mocks
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=get_output))
        self.mock_object(self._copy, 'get_progress')

        # run
        self._copy.copy_data(self._copy.src)

        # asserts
        self._copy.get_progress.assert_called_once_with()

        utils.execute.assert_has_calls([
            mock.call("ls", "-pA1", "--group-directories-first",
                      self._copy.src, run_as_root=True),
            mock.call("mkdir", "-p", os.path.join(self._copy.dest, "folder1/"),
                      run_as_root=True),
            mock.call("ls", "-pA1", "--group-directories-first",
                      os.path.join(self._copy.src, "folder1/"),
                      run_as_root=True),
            mock.call("stat", "-c", "%s",
                      os.path.join(self._copy.src, "file1"), run_as_root=True),
            mock.call("cp", "-P", "--preserve=all",
                      os.path.join(self._copy.src, "file1"),
                      os.path.join(self._copy.dest, "file1"), run_as_root=True)
        ])

    def test_copy_data_cancelled_1(self):

        self._copy.cancelled = True

        # run
        self._copy.copy_data(self._copy.src)

        # reset
        self._copy.cancelled = False

    def test_copy_data_cancelled_2(self):

        def ls_output(*args, **kwargs):
            self._copy.cancelled = True
            return "folder1/", ""

        # mocks
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=ls_output))

        # run
        self._copy.copy_data(self._copy.src)

        # asserts
        utils.execute.assert_called_once_with(
            "ls", "-pA1", "--group-directories-first", self._copy.src,
            run_as_root=True)

        # reset
        self._copy.cancelled = False

    def test_copy_stats(self):

        values = [("folder1/\nitem/\nfile1\nitem", ""),
                  ("", ""),
                  "",
                  "",
                  "",
                  "",
                  "",
                  ""]

        def get_output(*args, **kwargs):
            return values.pop(0)

        # mocks
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=get_output))

        # run
        self._copy.copy_stats(self._copy.src)

        # asserts
        utils.execute.assert_has_calls([
            mock.call("ls", "-pA1", "--group-directories-first",
                      self._copy.src, run_as_root=True),
            mock.call("ls", "-pA1", "--group-directories-first",
                      os.path.join(self._copy.src, "folder1/"),
                      run_as_root=True),
            mock.call(
                "chmod",
                "--reference=%s" % os.path.join(self._copy.src, "folder1/"),
                os.path.join(self._copy.dest, "folder1/"),
                run_as_root=True),
            mock.call(
                "touch",
                "--reference=%s" % os.path.join(self._copy.src, "folder1/"),
                os.path.join(self._copy.dest, "folder1/"),
                run_as_root=True),
            mock.call(
                "chown",
                "--reference=%s" % os.path.join(self._copy.src, "folder1/"),
                os.path.join(self._copy.dest, "folder1/"),
                run_as_root=True),
        ])

    def test_copy_stats_cancelled_1(self):

        self._copy.cancelled = True

        # run
        self._copy.copy_stats(self._copy.src)

        # reset
        self._copy.cancelled = False

    def test_copy_stats_cancelled_2(self):

        def ls_output(*args, **kwargs):
            self._copy.cancelled = True
            return "folder1/", ""

        # mocks
        self.mock_object(utils, 'execute', mock.Mock(
            side_effect=ls_output))

        # run
        self._copy.copy_stats(self._copy.src)

        # asserts
        utils.execute.assert_called_once_with(
            "ls", "-pA1", "--group-directories-first", self._copy.src,
            run_as_root=True)

        # reset
        self._copy.cancelled = False

    def test_run(self):

        # mocks
        self.mock_object(self._copy, 'get_total_size')
        self.mock_object(self._copy, 'copy_data')
        self.mock_object(self._copy, 'copy_stats')
        self.mock_object(self._copy, 'get_progress')

        # run
        self._copy.run()

        # asserts
        self.assertTrue(data_utils.LOG.info.called)
        self._copy.get_total_size.assert_called_once_with(self._copy.src)
        self._copy.copy_data.assert_called_once_with(self._copy.src)
        self._copy.copy_stats.assert_called_once_with(self._copy.src)
        self._copy.get_progress.assert_called_once_with()
