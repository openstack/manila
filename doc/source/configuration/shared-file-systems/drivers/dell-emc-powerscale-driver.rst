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

- Mount snapshot.

- Mount point name.

- Schedule Dedupe job for a share

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

Mount Snapshot
~~~~~~~~~~~~~~

To enable snapshot-mount support for a share type, set the following extra
specification:

.. code-block:: ini

    openstack share type set <share_type> --extra-spec \
    mount_snapshot_support="<is> True"

Access behavior

- Mounted snapshots are always read-only.
- For NFS and CIFS, IP-based access rules are applied.
- For CIFS, user-based access rules are also supported.

Mount Point Name
~~~~~~~~~~~~~~~~

PowerScale system supports providing a custom mount point name for
both NFS and CIFS protocols.
The mount point name will be prepended and will become the share's mount path.

.. code-block:: ini

    openstack share type set <share_type> --extra-spec \
    mount_point_name_support="<is> True"
    provisioning:mount_point_prefix=<prefix>

For detailed usage instructions, refer to the Manila administration
documentation:

:doc:`/admin/share_mount_point_name`

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

Schedule Dedupe job for a share
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To schedule Dedupe job for NFS/CIFS share, create share type with extra-specs

.. code-block:: ini

    openstack share type create <share_type_name> False --extra-specs \
    dedupe=True

    openstack share create <protocol> <size>
    --name <share_name> --share-type <share_type>

On PowerScale, Dedupe job will be scheduled weekly
on Sunday at 12:00 AM by default for the created
NFS/CIFS share.

Add the parameter below to set a schedule.

Format
every <N> weeks on <day1>[, day2, ...] at <time>
.. code-block:: ini

    powerscale_dedupe_schedule = "every 2 weeks on wednesday, sunday at 12:00 AM"
    powerscale_dedupe_schedule = "every 4 weeks on wednesday, sunday, monday, tuesday at 09:00 PM"

every <N> days at <time>
.. code-block:: ini

    powerscale_dedupe_schedule = "every 4 days at 09:10 PM"

the <ordinal> <weekday> every <N> months at <time>
.. code-block:: ini

    powerscale_dedupe_schedule = "the 3rd sunday every 4 month at 09:10 PM"
    powerscale_dedupe_schedule = "the 15th weekday every 4 month at 09:10 PM"

the <day> every <N> months at <time>
.. code-block:: ini

    powerscale_dedupe_schedule = "the 15 every 4 month at 09:10 PM"

yearly on the <ordinal> <weekday> of <month> at <time>
.. code-block:: ini

    powerscale_dedupe_schedule = "yearly on the 4th sunday of january at 09:10 PM"

yearly on the <day> of <month> at <time>
.. code-block:: ini

    powerscale_dedupe_schedule = "yearly on the 15 of january at 09:10 PM"

If you do not want to schedule dedupe job, then do not
provide extra spec while creating share type.

Managing a share : If you are trying to manage a share which is dedupe enabled,
then, please associate it with openstack share type with dedupe enabled and vice-versa
otherwise manage will result in error.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-emc.inc
