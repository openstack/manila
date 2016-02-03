# Copyright 2015, Hitachi Data Systems.
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

from oslo_log import log
import six

from manila import utils

LOG = log.getLogger(__name__)


class Copy(object):

    def __init__(self, src, dest, ignore_list):
        self.src = src
        self.dest = dest
        self.total_size = 0
        self.current_size = 0
        self.files = []
        self.dirs = []
        self.current_copy = None
        self.ignore_list = ignore_list
        self.cancelled = False

    def get_progress(self):

        if self.current_copy is not None:

            try:
                size, err = utils.execute("stat", "-c", "%s",
                                          self.current_copy['file_path'],
                                          run_as_root=True)
                size = int(size)
            except utils.processutils.ProcessExecutionError:
                size = 0

            total_progress = 0
            if self.total_size > 0:
                total_progress = self.current_size * 100 / self.total_size
            current_file_progress = 0
            if self.current_copy['size'] > 0:
                current_file_progress = size * 100 / self.current_copy['size']
            current_file_path = self.current_copy['file_path']

            progress = {
                'total_progress': total_progress,
                'current_file_path': current_file_path,
                'current_file_progress': current_file_progress
            }

            return progress
        else:
            return {'total_progress': 100}

    def cancel(self):

        self.cancelled = True

    def run(self):

        self.get_total_size(self.src)
        self.copy_data(self.src)
        self.copy_stats(self.src)

        LOG.info(six.text_type(self.get_progress()))

    def get_total_size(self, path):
        if self.cancelled:
            return
        out, err = utils.execute(
            "ls", "-pA1", "--group-directories-first", path,
            run_as_root=True)
        for line in out.split('\n'):
            if self.cancelled:
                return
            if len(line) == 0:
                continue
            src_item = os.path.join(path, line)
            if line[-1] == '/':
                if line[0:-1] in self.ignore_list:
                    continue
                self.get_total_size(src_item)
            else:
                if line in self.ignore_list:
                    continue
                size, err = utils.execute("stat", "-c", "%s", src_item,
                                          run_as_root=True)
                self.total_size += int(size)

    def copy_data(self, path):
        if self.cancelled:
            return
        out, err = utils.execute(
            "ls", "-pA1", "--group-directories-first", path,
            run_as_root=True)
        for line in out.split('\n'):
            if self.cancelled:
                return
            if len(line) == 0:
                continue
            src_item = os.path.join(path, line)
            dest_item = src_item.replace(self.src, self.dest)
            if line[-1] == '/':
                if line[0:-1] in self.ignore_list:
                    continue
                utils.execute("mkdir", "-p", dest_item, run_as_root=True)
                self.copy_data(src_item)
            else:
                if line in self.ignore_list:
                    continue
                size, err = utils.execute("stat", "-c", "%s", src_item,
                                          run_as_root=True)

                self.current_copy = {'file_path': dest_item,
                                     'size': int(size)}

                utils.execute("cp", "-P", "--preserve=all", src_item,
                              dest_item, run_as_root=True)

                self.current_size += int(size)

                LOG.info(six.text_type(self.get_progress()))

    def copy_stats(self, path):
        if self.cancelled:
            return
        out, err = utils.execute(
            "ls", "-pA1", "--group-directories-first", path,
            run_as_root=True)
        for line in out.split('\n'):
            if self.cancelled:
                return
            if len(line) == 0:
                continue
            src_item = os.path.join(path, line)
            dest_item = src_item.replace(self.src, self.dest)
            # NOTE(ganso): Should re-apply attributes for folders.
            if line[-1] == '/':
                if line[0:-1] in self.ignore_list:
                    continue
                self.copy_stats(src_item)
                utils.execute("chmod", "--reference=%s" % src_item, dest_item,
                              run_as_root=True)
                utils.execute("touch", "--reference=%s" % src_item, dest_item,
                              run_as_root=True)
                utils.execute("chown", "--reference=%s" % src_item, dest_item,
                              run_as_root=True)
