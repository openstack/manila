..
      Copyright 2014 Mirantis Inc.
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

NetApp Clustered Data ONTAP
===========================

The Manila Shared Filesystem Management Service can be configured to use
NetApp clustered Data ONTAP version 8.

Network approach
----------------

L3 connectivity between the storage cluster and Manila host should exist, and
VLAN segmentation should be configured.

The clustered Data ONTAP driver creates storage virtual machines (SVM,
previously known as vServers) as representations of Manila share server
interface, configures logical interfaces (LIFs) and stores shares there.

Supported shared filesystems
----------------------------

- NFS (access by IP);
- CIFS (authentication by user);

Required licenses
-----------------

- NFS
- CIFS
- FlexClone

Known restrictions
------------------

- For CIFS shares an external active directory service is required. Its data
  should be provided via security-service that is attached to used
  share-network.
- Share access rule by user for CIFS shares can be created only for existing
  user in active directory.
- To be able to configure clients to security services, the time on these
  external security services and storage should be synchronized. The maximum
  allowed clock skew is 5 minutes.

The :mod:`manila.share.drivers.netapp.dataontap.cluster_mode.drv_multi_svm.py` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.netapp.dataontap.cluster_mode.drv_multi_svm
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
