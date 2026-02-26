..
      Copyright 2025 Hewlett Packard Enterprise Development LP

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

HPE Alletra MP B10000 Share Driver
===================================

The HPE Alletra MP B10000 Manila driver provides NFS file services
to OpenStack using the HPE Alletra MP B10000 file service capabilities.

Supported Operations
--------------------

The following operations are supported with HPE Alletra MP B10000:

- Create/delete NFS shares
- Allow/deny NFS share access
- Extend shares
- Manage existing shares
- Unmanage shares

Share networks are not supported. Shares are created directly on the HPE
Alletra MP B10000 array without the use of a share server or service VM.
Network connectivity is set up outside of Manila.

.. note::

   Most operations described in this document can also be performed through
   the OpenStack Horizon dashboard. This document focuses on CLI commands.

Share Types
-----------

When creating a share, the share type will be used to determine where and how
the share will be created.

Manila requires that the share type includes the ``driver_handles_share_servers``
extra-spec. This ensures that the share is created on a backend that supports
the requested driver_handles_share_servers (share networks) capability. For the
HPE Alletra MP B10000 driver, this option must be set to ``False``.

Creating a Share Type
~~~~~~~~~~~~~~~~~~~~~

To create a share type for the HPE Alletra MP B10000 backend:

.. code-block:: console

   $ openstack share type create alletra_nfs False
   $ openstack share type set alletra_nfs --extra-specs share_backend_name=hpealletra1

Share Type Extra Specs
~~~~~~~~~~~~~~~~~~~~~~

The following driver-specific extra specs are supported by Alletra MP B10000:

**hpe_alletra_b10000:reduce**
   When the value is set to ``true`` (or ``false``), shares of
   this reduce type are created on the backend. The reduce setting is applied
   at share creation time and cannot be changed for existing shares.

   The ``reduce`` parameter controls the ``compression`` and ``dedupe`` capabilities
   of the share:

   - If reduce = true: compression = true, dedupe = true
   - If reduce = false: compression = false, dedupe = false

   If the reduce key is not provided, its value defaults to ``true``.

   Alternatively, you can use the ``compression`` and ``dedupe`` parameters
   directly instead of ``reduce``, but you cannot specify both ``reduce`` and
   ``compression``/``dedupe`` in the same share type.

   Example using reduce:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs hpe_alletra_b10000:reduce=true

   Example using compression and dedupe as alternative:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs compression=true dedupe=true

**hpe_alletra_b10000:squash_option**
   The value can be set to ``root_squash``, ``all_squash``, or
   ``no_root_squash``. Any access rules added to the Alletra backend
   will be created with this squash option. If the share type is modified
   to change the squash option, the next share access rule update will use
   the new squash option value.

   If not provided, the squash option defaults to ``root_squash``.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs hpe_alletra_b10000:squash_option=root_squash

The following common extra specs are also supported by Alletra MP B10000:

**compression**
   Controls whether compression is enabled on the share.

   When specifying ``compression``, you must also specify ``dedupe`` with the
   same value (both ``true`` or both ``false``). You cannot use ``compression``
   together with ``hpe_alletra_b10000:reduce``.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs compression=true dedupe=true

**dedupe**
   Controls whether data deduplication is enabled on the share.

   When specifying ``dedupe``, you must also specify ``compression`` with the
   same value (both ``true`` or both ``false``). You cannot use ``dedupe``
   together with ``hpe_alletra_b10000:reduce``.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs dedupe=true compression=true

**thin_provisioning**
   Controls whether thin provisioning is enabled on the share.

   This extra spec must be set to ``true`` or not specified at all. Setting
   it to ``false`` is not supported by this driver.

   Example:

   .. code-block:: console

      $ openstack share type set alletra_nfs --extra-specs thin_provisioning=true

.. note::

   Modifying share type extra specs after shares have been created is not
   recommended, as it will cause inconsistency between the share type
   definition and the actual backend share properties. Backend share
   characteristics like reduce, compression, and dedupe cannot be changed
   after creation.

Managing Share Access
---------------------

A share must have access rules configured before it can be accessed by clients.
IP-based access rules are required for NFS shares.

.. note::

   When no Manila access rules are configured, the driver will block all IP addresses
   by setting a default access rule of 0.0.0.0 with read-only and root_squash
   permissions on the backend Alletra B10000 array. You must explicitly create
   access rules to allow client access.

For CLI commands and more information on managing access rules,
see :ref:`manage access to share <access_to_share>`.

Extending Shares
----------------

The driver supports extending shares to increase their size.

For CLI commands and more information on extending shares,
see :ref:`share resize <shared_file_systems_share_resize>`.

.. note::

   The share size shown in Manila includes filesystem metadata and other overhead.
   Client-usable space will be less than the displayed share size.

Managing Existing Shares
------------------------

The driver supports bringing existing shares on the HPE Alletra array
into Manila management using the manage operation.

Prerequisites for Manage Operation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before managing an existing share, ensure the following requirements are met:

#. **Share type compatibility**: The backend share ``reduce`` value must match
   the ``hpe_alletra_b10000:reduce`` value from the share type. If they don't
   match, the manage operation will fail. Associate the correct share type.
   Default reduce value (if share type doesn't have this key) is ``true``.
   Similarly, if the share type uses ``compression`` and ``dedupe`` parameters
   instead of ``reduce``, those values must also match the backend share's
   compression and deduplication settings.

#. **No existing access rules**: The backend share must have either an empty access
   rules list or only the default 0.0.0.0 access rule with read-only and root_squash.
   If other access rules exist, clear them from the backend share before managing:

   .. code-block:: console

      $ setsharesetting -remove <ipaddr_list> <sharesetting_name>

#. **Filesystem size alignment**: The filesystem size of the backend fileshare
   must be a multiple of 1024 MiB (1 GiB). If not, the manage operation will fail.
   Manila logs will indicate how much MiB to expand the backend filesystem.

   To expand size by a specific amount (e.g., 500 MiB):

   .. code-block:: console

      $ setfilesystem -size 500 <filesystem_name>

Ensure Shares Operation
-----------------------

The driver supports the ``ensure_shares`` operation, which validates that shares
exist on the backend and updates their status in Manila. Shares found on
the backend are updated with the latest export locations. Shares not found
on the backend are marked with ``error`` state.

The ensure_shares operation for the driver is executed only in case of
service restarts after configuration changes in /etc/manila/manila.conf.

If the backend fileshare export path changes due to file port IP change
or other reasons, the administrator must manually trigger the ensure shares
command in OpenStack to update the latest export paths.

Refer to :ref:`recalculating the shares export location <shared_file_systems_services_manage.rst>`
for details on manually triggering the ensure shares operation.

Driver Capabilities
-------------------

The HPE Alletra MP B10000 driver reports the following capabilities:

- Storage protocol: NFS
- driver_handles_share_servers: False
- Share extend support
- Manage/unmanage support

Restrictions and Limitations
----------------------------

The HPE Alletra MP B10000 driver has the following restrictions:

- Only NFS protocol is supported; CIFS/SMB is not supported
- Share networks are not supported (driver_handles_share_servers must be False)
- Share shrink is not currently supported
- Share migration is not supported
- Share replication is not supported
- Share groups and consistency groups are not supported
- Security services (LDAP, Active Directory, Kerberos) are not supported
- Only IP-based access rules are supported for NFS shares

Troubleshooting
---------------

Common Issues
~~~~~~~~~~~~~

**Share creation fails**
   - Verify the HPE Alletra MP B10000 file service is enabled
   - Check connectivity to the WSAPI endpoint
   - Ensure the configured user has sufficient permissions

**Access rules not working**
   - Verify network connectivity between client and array's file ports
   - Check that the IP address in the access rule is correct
   - Ensure the share type's squash_option is appropriate for your use case

**Manage operation fails**
   - Clear all access rules from the backend share
   - Verify filesystem size is a multiple of 1 GiB
   - Ensure share type's reduce value matches the backend share

The :mod:`manila.share.drivers.hpe.alletra_mp_b10000.hpe_alletra_driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.hpe.alletra_mp_b10000.hpe_alletra_driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
