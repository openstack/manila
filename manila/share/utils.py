# Copyright (c) 2012 OpenStack Foundation
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

"""Share-related Utilities and helpers."""

import os
import shutil

from oslo_log import log
import six

LOG = log.getLogger(__name__)

DEFAULT_POOL_NAME = '_pool0'


def extract_host(host, level='backend', use_default_pool_name=False):
    """Extract Host, Backend or Pool information from host string.

    :param host: String for host, which could include host@backend#pool info
    :param level: Indicate which level of information should be extracted
                  from host string. Level can be 'host', 'backend' or 'pool',
                  default value is 'backend'
    :param use_default_pool_name: This flag specifies what to do
                              if level == 'pool' and there is no 'pool' info
                              encoded in host string.  default_pool_name=True
                              will return DEFAULT_POOL_NAME, otherwise it will
                              return None. Default value of this parameter
                              is False.
    :return: expected level of information

    For example:
        host = 'HostA@BackendB#PoolC'
        ret = extract_host(host, 'host')
        # ret is 'HostA'
        ret = extract_host(host, 'backend')
        # ret is 'HostA@BackendB'
        ret = extract_host(host, 'pool')
        # ret is 'PoolC'

        host = 'HostX@BackendY'
        ret = extract_host(host, 'pool')
        # ret is None
        ret = extract_host(host, 'pool', True)
        # ret is '_pool0'
    """
    if level == 'host':
        # Make sure pool is not included
        hst = host.split('#')[0]
        return hst.split('@')[0]
    elif level == 'backend':
        return host.split('#')[0]
    elif level == 'pool':
        lst = host.split('#')
        if len(lst) == 2:
            return lst[1]
        elif use_default_pool_name is True:
            return DEFAULT_POOL_NAME
        else:
            return None


def append_host(host, pool):
    """Encode pool into host info."""
    if not host or not pool:
        return host

    new_host = "#".join([host, pool])
    return new_host


class Copy(object):

    def __init__(self, src, dest, ignore_list):
        self.src = src
        self.dest = dest
        self.totalSize = 0
        self.currentSize = 0
        self.files = []
        self.dirs = []
        self.currentCopy = None
        self.ignoreList = ignore_list

    def get_progress(self):

        if self.currentCopy is not None:

            try:
                (mode, ino, dev, nlink, uid, gid, size, atime, mtime,
                 ctime) = os.stat(self.currentCopy['file_path'])

            except OSError:
                size = 0

            total_progress = 0
            if self.totalSize > 0:
                total_progress = self.currentSize * 100 / self.totalSize
            current_file_progress = 0
            if self.currentCopy['size'] > 0:
                current_file_progress = size * 100 / self.currentCopy['size']
            current_file_path = six.text_type(self.currentCopy['file_path'])

            progress = {
                'total_progress': total_progress,
                'current_file_path': current_file_path,
                'current_file_progress': current_file_progress
            }

            return progress
        else:
            return {'total_progress': 100}

    def run(self):

        self.explore(self.src)
        self.copy(self.src, self.dest)

        LOG.info((six.text_type(self.get_progress())))

    def copy(self, src, dest):

        # Create dirs with max permissions so files can be copied
        for dir_item in self.dirs:
            new_dir = dir_item['name'].replace(src, dest)
            os.mkdir(new_dir)

        for file_item in self.files:

            file_path = file_item['name'].replace(src, dest)
            self.currentCopy = {'file_path': file_path,
                                'size': file_item['attr']}

            LOG.info(six.text_type(self.get_progress()))

            shutil.copy2(file_item['name'],
                         file_item['name'].replace(src, dest))
            self.currentSize += file_item['attr']

        # Set permissions to dirs
        for dir_item in self.dirs:
            new_dir = dir_item['name'].replace(src, dest)
            shutil.copystat(dir_item['name'], new_dir)

    def explore(self, path):

        for dirpath, dirnames, filenames in os.walk(path):

            for dirname in dirnames:
                if dirname not in self.ignoreList:
                    dir_item = os.path.join(dirpath, dirname)
                    (mode, ino, dev, nlink, uid, gid, size, atime, mtime,
                     ctime) = os.stat(dir_item)
                    self.dirs.append({'name': dir_item,
                                      'attr': mode})

            for filename in filenames:
                if filename not in self.ignoreList:
                    file_item = os.path.join(dirpath, filename)
                    (mode, ino, dev, nlink, uid, gid, size, atime, mtime,
                     ctime) = os.stat(file_item)
                    self.files.append({'name': file_item,
                                       'attr': size})
                    self.totalSize += size
