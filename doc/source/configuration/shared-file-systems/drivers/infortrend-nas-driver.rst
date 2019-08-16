========================
Infortrend Manila driver
========================

The `Infortrend <http://www.infortrend.com/global>`__ Manila driver
provides NFS and CIFS shared file systems to OpenStack.

Requirements
~~~~~~~~~~~~

To use the Infortrend Manila driver, the following items are required:

- GS/GSe Family firmware version v73.1.0-4 and later.

- Configure at least one channel for shared file systems.

Supported shared filesystems and operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This driver supports NFS and CIFS shares.

The following operations are supported:

- Create a share.

- Delete a share.

- Allow share access.

  Note the following limitations:

  - Only IP access type is supported for NFS.

  - Only user access type is supported for CIFS.

- Deny share access.

- Manage a share.

- Unmanage a share.

- Extend a share.

- Shrink a share.

Restrictions
~~~~~~~~~~~~

The Infortrend manila driver has the following restrictions:

-  Only IP access type is supported for NFS.

-  Only user access type is supported for CIFS.

-  Only file-level data service channel can offer the NAS service.

Driver configuration
~~~~~~~~~~~~~~~~~~~~

On ``manila-share`` nodes, set the following in your
``/etc/manila/manila.conf``, and use the following options to configure it:

Driver options
--------------

.. include:: ../../tables/manila-infortrend.inc

Back-end configuration example
------------------------------

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = ift-manila
   enabled_share_protocols = NFS, CIFS

   [ift-manila]
   share_backend_name = ift-manila
   share_driver = manila.share.drivers.infortrend.driver.InfortrendNASDriver
   driver_handles_share_servers = False
   infortrend_nas_ip = FAKE_IP
   infortrend_nas_user = FAKE_USER
   infortrend_nas_password = FAKE_PASS
   infortrend_share_pools = pool-1, pool-2
   infortrend_share_channels = 0, 1
