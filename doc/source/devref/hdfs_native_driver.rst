..
      Copyright 2015 Intel, Corp.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

HDFS native driver
==================

HDFS native driver is a plugin based on the OpenStack manila service, which uses
Hadoop distributed file system (HDFS), a distributed file system designed to hold
very large amounts of data, and provide high-throughput access to the data.

A manila share in this driver is a subdirectory in hdfs root directory. Instances
talk directly to the HDFS storage backend with 'hdfs' protocol. And access to each
share is allowed by user based access type, which is aligned with HDFS ACLs to
support access control of multiple users and groups.

Network configuration
---------------------

The storage backend and manila hosts should be in a flat network, otherwise, the L3
connectivity between them should exist.

Supported shared filesystems
----------------------------

- HDFS (authentication by user)

Supported Operations
--------------------

- Create HDFS share
- Delete HDFS share
- Allow HDFS Share access
  * Only support user access type
  * Support level of access (ro/rw)
- Deny HDFS Share access
- Create snapshot
- Delete snapshot
- Create share from snapshot
- Extend share

Requirements
------------

- Install HDFS package, version >= 2.4.x, on the storage backend
- To enable access control, the HDFS file system must have ACLs enabled
- Establish network connection between the manila host and storage backend

Manila driver configuration
---------------------------

- `share_driver` = manila.share.drivers.hdfs.hdfs_native.HDFSNativeShareDriver
- `hdfs_namenode_ip` = the IP address of the HDFS namenode, and only single
    namenode is supported now
- `hdfs_namenode_port` = the port of the HDFS namenode service
- `hdfs_ssh_port` = HDFS namenode SSH port
- `hdfs_ssh_name` = HDFS namenode SSH login name
- `hdfs_ssh_pw` = HDFS namenode SSH login password, this parameter is not
    necessary, if the following `hdfs_ssh_private_key` is configured
- `hdfs_ssh_private_key` = Path to the HDFS namenode private key to ssh login

Known Restrictions
------------------

- This driver does not support network segmented multi-tenancy model. Instead
  multi-tenancy is supported by the tenant specific user authentication
- Only support for single HDFS namenode in Kilo release

The :mod:`manila.share.drivers.hdfs.hdfs_native` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.hdfs.hdfs_native
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

