===================
NexentaStor5 Driver
===================

Nexentastor5 can be used as a storage back end for the OpenStack Shared File
System service. Shares in the Shared File System service are mapped 1:1
to Nexentastor5 filesystems. Access is provided via NFS protocol and IP-based
authentication.

Network approach
~~~~~~~~~~~~~~~~

L3 connectivity between the storage back end and the host running the
Shared File Systems share service should exist.


Supported shared filesystems and operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The drivers supports NFS shares.

The following operations are supported:

- Create NFS share

- Delete share

- Extend share

- Shrink share

- Allow share access

  Note the following limitation:

    * Only IP based access is supported (ro/rw).

- Deny share access

- Create snapshot

- Revert to snapshot

- Delete snapshot

- Create share from snapshot

- Manage share

- Unmanage share

Requirements
~~~~~~~~~~~~

- NexentaStor 5.x Appliance pre-provisioned and licensed

- Pool and parent filesystem configured (this filesystem will contain
  all manila shares)

Restrictions
~~~~~~~~~~~~
- Only IP share access control is allowed for NFS shares.

Configuration
~~~~~~~~~~~~~~

.. code-block:: ini

   enabled_share_backends = NexentaStor5

Create the new back end configuration section, in this case named
``NexentaStor5``:

.. code-block:: ini

   [NexentaStor5]

    share_backend_name = NexentaStor5
    driver_handles_share_servers = False
    nexenta_folder = manila
    share_driver = manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver
    nexenta_rest_addresses = 10.3.1.1,10.3.1.2
    nexenta_nas_host = 10.3.1.10
    nexenta_rest_port = 8443
    nexenta_pool = pool1
    nexenta_nfs = True
    nexenta_user = admin
    nexenta_password = secret_password
    nexenta_thin_provisioning = True

More information can be found at the `Nexenta documentation webpage
<https://nexenta.github.io>`.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-nexentastor5.inc
