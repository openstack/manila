.. _shared_file_systems_intro:

===========
Admin Guide
===========

Shared File Systems service provides a set of services for management of
shared file systems in a multi-project cloud environment. The service resembles
OpenStack block-based storage management from the OpenStack Block Storage
service project. With the Shared File Systems service, you can
create a remote file system, mount the file system on your instances, and then
read and write data from your instances to and from your file system.

The Shared File Systems service serves same purpose as the Amazon Elastic File
System (EFS) does.

The Shared File Systems service can run in a single-node or multiple
node configuration.  The Shared File Systems service can be configured
to provision shares from one or more back ends, so it is required to
declare at least one back end. Shared File System service contains
several configurable components.

It is important to understand these components:

* Share networks
* Shares
* Multi-tenancy
* Back ends

The Shared File Systems service consists of four types of services,
most of which are similar to those of the Block Storage service:

- ``manila-api``
- ``manila-data``
- ``manila-scheduler``
- ``manila-share``

Installation of first three - ``manila-api``, ``manila-data``, and
``manila-scheduler`` is common for almost all deployments. But configuration
of ``manila-share`` is backend-specific and can differ from deployment to
deployment.

.. toctree::
   :maxdepth: 1

   shared-file-systems-key-concepts.rst
   shared-file-systems-share-management.rst
   shared-file-systems-share-migration.rst
   shared-file-systems-share-types.rst
   shared-file-systems-snapshots.rst
   shared-file-systems-security-services.rst
   shared-file-systems-share-replication.rst
   shared-file-systems-multi-backend.rst
   shared-file-systems-networking.rst
   shared-file-systems-troubleshoot.rst
   share_back_ends_feature_support_mapping
   capabilities_and_extra_specs
   group_capabilities_and_extra_specs
   export_location_metadata

Supported share back ends
-------------------------

The manila share service must be configured to use drivers for one or
more storage back ends, as described in general terms below.  See the
drivers section in the `Configuration Reference
<https://docs.openstack.org/manila/latest/configuration/shared-file-systems/drivers.html>`_
for detailed configuration options for
each back end.

.. toctree::
   :maxdepth: 3

   container_driver
   zfs_on_linux_driver
   netapp_cluster_mode_driver
   emc_isilon_driver
   emc_vnx_driver
   emc_unity_driver
   generic_driver
   glusterfs_driver
   glusterfs_native_driver
   cephfs_driver
   gpfs_driver
   huawei_nas_driver
   hdfs_native_driver
   hitachi_hnas_driver
   hpe_3par_driver
   tegile_driver

