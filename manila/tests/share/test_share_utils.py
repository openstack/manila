# Copyright 2011 OpenStack Foundation
# Copyright (c) 2015 Rushil Chugh
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

"""Tests For miscellaneous util methods used with share."""

import os
import shutil

import mock

from manila.share import utils as share_utils
from manila import test


class ShareUtilsTestCase(test.TestCase):
    def test_extract_host_without_pool(self):
        host = 'Host@Backend'
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host))

    def test_extract_host_only_return_host(self):
        host = 'Host@Backend'
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host'))

    def test_extract_host_only_return_pool(self):
        host = 'Host@Backend'
        self.assertIsNone(
            share_utils.extract_host(host, 'pool'))

    def test_extract_host_only_return_backend(self):
        host = 'Host@Backend'
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host, 'backend'))

    def test_extract_host_missing_backend_and_pool(self):
        host = 'Host'
        # Default level is 'backend'
        self.assertEqual(
            'Host', share_utils.extract_host(host))

    def test_extract_host_missing_backend(self):
        host = 'Host#Pool'
        self.assertEqual(
            'Host', share_utils.extract_host(host))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host'))

    def test_extract_host_missing_backend_only_return_backend(self):
        host = 'Host#Pool'
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'backend'))

    def test_extract_host_missing_backend_only_return_pool(self):
        host = 'Host#Pool'
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool'))
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool', True))

    def test_extract_host_missing_pool(self):
        host = 'Host@Backend'
        self.assertIsNone(
            share_utils.extract_host(host, 'pool'))

    def test_extract_host_missing_pool_use_default_pool(self):
        host = 'Host@Backend'
        self.assertEqual(
            '_pool0', share_utils.extract_host(host, 'pool', True))

    def test_extract_host_with_default_pool(self):
        host = 'Host'
        # Default_pool_name doesn't work for level other than 'pool'
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host', True))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host', False))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'backend', True))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'backend', False))

    def test_extract_host_with_pool(self):
        host = 'Host@Backend#Pool'
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host'))
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host, 'backend'),)
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool'))
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool', True))

    def test_append_host_with_host_and_pool(self):
        host = 'Host'
        pool = 'Pool'
        expected = 'Host#Pool'
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_append_host_with_host(self):
        host = 'Host'
        pool = None
        expected = 'Host'
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_append_host_with_pool(self):
        host = None
        pool = 'pool'
        expected = None
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_append_host_with_no_values(self):
        host = None
        pool = None
        expected = None
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))


class CopyClassTestCase(test.TestCase):
    def setUp(self):
        super(CopyClassTestCase, self).setUp()
        src = '/path/fake/src'
        dest = '/path/fake/dst'
        ignore_list = ['item']
        self._copy = share_utils.Copy(src, dest, ignore_list)
        self._copy.totalSize = 10000
        self._copy.currentSize = 100
        self._copy.files = [{'name': '/fileA', 'attr': 100},
                            {'name': '/fileB', 'attr': 150},
                            {'name': '/fileC', 'attr': 200}]
        self._copy.dirs = [{'name': '/fakeA', 'attr': 777},
                           {'name': '/fakeB', 'attr': 666},
                           {'name': '/fakeC', 'attr': 767}]
        self._copy.currentCopy = {'file_path': '/fake/path', 'size': 100}

        self.stat_result = [777, 'ino', 'dev', 'nlink', 'uid',
                            'gid', 100, 'at', 'mt', 'ct']

        self.mock_log = self.mock_object(share_utils, 'LOG')

    def test_get_progress(self):
        expected = {'total_progress': 1,
                    'current_file_path': '/fake/path',
                    'current_file_progress': 100}

        self.mock_object(os, 'stat', mock.Mock(return_value=self.stat_result))

        out = self._copy.get_progress()

        self.assertEqual(expected, out)
        os.stat.assert_called_once_with('/fake/path')

    def test_get_progress_current_copy_none(self):
        self._copy.currentCopy = None
        expected = {'total_progress': 100}

        out = self._copy.get_progress()

        self.assertEqual(expected, out)

    def test_get_progress_os_exception(self):
        expected = {'total_progress': 1,
                    'current_file_path': '/fake/path',
                    'current_file_progress': 0}

        self.mock_object(os, 'stat', mock.Mock(side_effect=OSError))

        out = self._copy.get_progress()
        os.stat.assert_called_once_with('/fake/path')
        self.assertEqual(expected, out)

    def test_run(self):
        dirpath = '/dirpath1'
        dirnames = [('dir1', 'dir2'), ('dir3', 'dir4')]
        filenames = [('file1.txt', 'file2.exe'), ('file3.txt', 'file4.exe')]
        os_walk_return = [(dirpath, dirnames[0], filenames[0]),
                          (dirpath, dirnames[1], filenames[1])]

        self.mock_object(shutil, 'copy2', mock.Mock())
        self.mock_object(shutil, 'copystat', mock.Mock())
        self.mock_object(os, 'stat', mock.Mock(return_value=self.stat_result))
        self.mock_object(os, 'walk', mock.Mock(return_value=os_walk_return))
        self.mock_object(os, 'mkdir', mock.Mock())

        self._copy.run()

        self.assertTrue(self.mock_log.info.called)
        os.walk.assert_called_once_with('/path/fake/src')
        # os.stats called in explore and get_progress functions
        self.assertEqual(16, os.stat.call_count)

    def test_copy(self):
        src = '/path/fake/src'
        dest = '/path/fake/dst'

        self.mock_object(os, 'stat', mock.Mock(return_value=self.stat_result))
        self.mock_object(os, 'mkdir', mock.Mock())
        self.mock_object(shutil, 'copy2', mock.Mock())
        self.mock_object(shutil, 'copystat', mock.Mock())

        self._copy.copy(src, dest)

        self.assertTrue(self.mock_log.info.called)
        # shutil.copystat should be called 3 times.
        # Once for each entry in self._copy.dirs
        self.assertEqual(3, shutil.copystat.call_count)
        # os.stat should be called 3 times.
        # Once for each entry in self._copy.files
        self.assertEqual(3, os.stat.call_count)
        self.assertEqual(3, os.mkdir.call_count)

        args = ('/fileA', '/fileB', '/fileC')
        os.stat.assert_has_calls([mock.call(a) for a in args])
        args = ('/fakeA', '/fakeB', '/fakeC')
        os.mkdir.assert_has_calls([mock.call(a) for a in args])

    def test_explore(self):
        path = '/dirpath1'
        dirpath = '/dirpath1'
        dirnames = [('dir1', 'dir2'), ('dir3', 'dir4')]
        filenames = [('file1.txt', 'file2.exe'), ('file3.txt', 'file4.exe')]
        os_walk_return = [(dirpath, dirnames[0], filenames[0]),
                          (dirpath, dirnames[1], filenames[1])]

        self.mock_object(os, 'stat', mock.Mock(return_value=self.stat_result))
        self.mock_object(os, 'walk', mock.Mock(return_value=os_walk_return))

        self._copy.explore(path)

        os.walk.assert_called_once_with('/dirpath1')
        # Function os.stat should be called 8 times.
        # 4 times for dirname in dirnames, and 4 times for
        # filename in filenames
        self.assertEqual(8, os.stat.call_count)

        args = ('/dirpath1/dir1', '/dirpath1/dir2', '/dirpath1/file1.txt',
                '/dirpath1/file2.exe', '/dirpath1/dir3', '/dirpath1/dir4',
                '/dirpath1/file3.txt', '/dirpath1/file4.exe')
        os.stat.assert_has_calls([mock.call(a) for a in args])
