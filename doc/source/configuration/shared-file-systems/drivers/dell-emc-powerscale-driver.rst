======================
Dell PowerScale driver
======================

The EMC Shared File Systems driver framework (EMCShareDriver) utilizes
Dell storage products to provide shared file systems to OpenStack. The
EMC driver is a plug-in based driver which is designed to use different
plug-ins to manage different Dell storage products.

The PowerScale driver is a plug-in for the EMC framework which allows the
Shared File Systems service to interface with an PowerScale back end to
provide a shared filesystem. The EMC driver framework with the PowerScale
plug-in is referred to as the ``PowerScale Driver`` in this document.

This PowerScale Driver interfaces with an PowerScale cluster via the REST
PowerScale
Platform API (PAPI) and the RESTful Access to Namespace API (RAN).

Requirements
~~~~~~~~~~~~

- PowerScale cluster running OneFS 9.10 or higher

Supported shared filesystems and operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The drivers supports CIFS and NFS shares.

The following operations are supported:

- Create a share.

- Delete a share.

- Allow share access.

  Note the following limitations:

  - Only IP access type is supported.
  - Only read-write access is supported.

- Deny share access.

- Create a snapshot.

- Delete a snapshot.

- Create a share from a snapshot.

- Ensure shares.

- Shrink share.

- Manage/Unmanage snapshot

- Manage and Unmanage CIFS/NFS share.

Back end configuration
~~~~~~~~~~~~~~~~~~~~~~

The following parameters need to be configured in the Shared File
Systems service configuration file for the PowerScale driver:

.. code-block:: ini

   share_driver = manila.share.drivers.emc.driver.EMCShareDriver
   emc_share_backend = powerscale
   emc_nas_server = <IP address of PowerScale cluster>
   emc_nas_login = <username>
   emc_nas_password = <password>

Thin Provisioning
~~~~~~~~~~~~~~~~~

PowerScale systems have thin provisioning enabled by default.
Add the parameter below to set an advisory limit.

.. code-block:: ini

    powerscale_threshold_limit = <threshold percentage value>

Manage and Unmanage existing shares
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PowerScale Manila driver supports importing pre-existing NFS/CIFS
exports into Manila ("manage existing") and ceasing management of a
managed share ("unmanage") without deleting the underlying export on
PowerScale. Managing registers an external export with Manila using the
service host, protocol, and export path; unmanaging removes only Manila
metadata and is non-disruptive to clients.

.. warning::

   **Supported only when the export points to the driver's container path.**
   The PowerScale driver will manage (or unmanage) an existing NFS/CIFS
   export **only if** the backend directory of that export is exactly the
   driver's container path:

   This is to prevent follow‑up operations (for example, **extend** or **shrink**)
   from failing later because quotas would be applied on the wrong directory.

Managing and unmanaging existing shares is performed using the OpenStack
Manila API or CLI.

For detailed usage instructions, refer to the Manila administration
documentation:

:doc:`/admin/shared-file-systems-manage-and-unmanage-share`

Notes and behavior
------------------
* Unmanage does not delete the export; clients remain connected.

Shrink a share
~~~~~~~~~~~~~~

Overview
--------
Shrinking reduces the size (GiB) of an existing Manila share to a
smaller value. The operation enforces quota limits and rejects invalid
sizes (e.g., 0 or any value greater than the current size).

Limitations and behavior
------------------------
* New size must be a positive integer **less than** the current size and
  within quotas.
* During the operation, the share status transitions to **shrinking**
  and returns to **available** on success.

For information on resizing shares, refer to the OpenStack Manila
administration guide:
:doc:`/admin/shared-file-systems-share-resize`

Restrictions
~~~~~~~~~~~~

The PowerScale driver has the following restrictions:

-  Only IP access type is supported for NFS and CIFS.

-  Only FLAT network is supported.

-  Quotas are not yet supported.

To Manage and Unmanage an existing share snapshot
-------------------------------------------------
To manage a snapshot existing in PowerScale System, you need make sure the related
share is existing in OpenStack, otherwise need to manage share first.

For detailed usage instructions, refer to the Manila administration
documentation:

:doc:`/admin/shared-file-systems-manage-and-unmanage-snapshot`

.. note::
    - provider_location is the snapshot id in PowerScale system.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-emc.inc
