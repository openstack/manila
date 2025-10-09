=====================
Vastdata Share Driver
=====================

VAST Share Driver integrates OpenStack with
`VAST Data <https://www.vastdata.com>`__'s Storage System.
Shares in the Shared File System service
are mapped to directories on VAST,
and are accessed via NFS protocol using a Virtual IP Pool.

Supported shared filesystems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The driver supports NFS shares.

Operations supported
~~~~~~~~~~~~~~~~~~~~
The driver supports NFS shares.

The following operations are supported:

-  Create a share.

-  Delete a share.

-  Allow share access.

- Deny share access.

- Extend a share.

- Shrink a share.


Requirements
~~~~~~~~~~~~

- The Trash Folder Access functionality must be enabled on the VAST cluster.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-vastdata.inc


VAST Share Driver configuration example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example shows parameters in the ``manila.conf`` file
that are used to configure VAST Share Driver.
They include two options under ``[DEFAULT]`` and parameters under ``[vast]``.
Note that a real ``manila.conf`` file would also include
other parameters that are not specific to VAST Share Driver.

.. note::

   The ``vast_vippool_name`` parameter can be omitted from ``manila.conf``
   if you plan to specify different VIP pools per share type using the
   ``vast:vippool_name`` extra spec. See the Multitenancy support section
   for more details.

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = vast
   enabled_share_protocols = NFS

   [vast]
   share_driver = manila.share.drivers.vastdata.driver.VASTShareDriver
   share_backend_name = vast
   driver_handles_share_servers = False
   snapshot_support = True
   vast_mgmt_host = {vms_ip}
   vast_mgmt_port = {vms_port}
   vast_mgmt_user = {mgmt_user}
   vast_mgmt_password = {mgmt_password}
   vast_api_token = {vast_api_token}
   vast_vippool_name = {vip_pool}
   vast_root_export = {root_export}


Restart of the ``manila-share`` service is needed for the configuration
changes to take effect.


Pre-configurations for share support
------------------------------------

To create a file share, you need to:

Create the share type:

.. code-block:: console

    openstack share type create ${share_type_name} False \
        --extra-specs share_backend_name=${share_backend_name}

Create an NFS share:

.. code-block:: console

    openstack share create NFS ${size} --name ${share_name} --share-type ${share_type_name}

Multitenancy support via Share Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The VAST Share Driver supports multitenancy by allowing different share types
to use different VIP pools. This enables tenant isolation and provides
flexibility in network configuration.

VIP Pool Configuration
----------------------

The VIP pool can be specified in two ways:

1. **Global default** in ``manila.conf`` using ``vast_vippool_name``
2. **Per share type** using the ``vast:vippool_name`` extra spec

When both are specified, the share type extra spec takes precedence over
the configuration file setting.

Creating Share Types with Different VIP Pools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can create multiple share types, each using a different VIP pool for
multitenancy:

.. code-block:: console

    # Tenant A with dedicated VIP pool
    openstack share type create vast-tenant-a false \
        --extra-specs share_backend_name=vast \
        --extra-specs vast:vippool_name=vippool-tenant-a

    # Tenant B with dedicated VIP pool
    openstack share type create vast-tenant-b false \
        --extra-specs share_backend_name=vast \
        --extra-specs vast:vippool_name=vippool-tenant-b

Creating Shares with Specific VIP Pools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When creating a share, specify the share type to determine which VIP pool
will be used:

.. code-block:: console

    # Create a share for Tenant A (uses vippool-tenant-a)
    openstack share create NFS 100 \
        --name tenant-a-share \
        --share-type vast-tenant-a

    # Create a share for Tenant B (uses vippool-tenant-b)
    openstack share create NFS 50 \
        --name tenant-b-share \
        --share-type vast-tenant-b

This approach enables:

- **Network isolation** between different tenants or projects
- **Service differentiation** with different network configurations per tenant or environment
- **Flexible deployment** without modifying ``manila.conf``

.. note::

   If ``vast_vippool_name`` is not specified in ``manila.conf`` and a share
   is created without a share type that specifies ``vast:vippool_name``,
   the share creation will fail with an error indicating that a VIP pool
   must be specified.

Pre-Configurations for Snapshot support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The share type must have the following parameter specified:

- snapshot_support = True

You can specify it when creating a new share type:

.. code-block:: console

    openstack share type create ${share_type_name} false \
        --snapshot-support=true \
        --extra-specs share_backend_name=${share_backend_name}

Or you can add it to an existing share type:

.. code-block:: console

    openstack share type set ${share_type_name} --extra-specs snapshot_support=True


To snapshot a share and create share from the snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a share using a share type with snapshot_support=True.
Then, create a snapshot of the share using the command:

.. code-block:: console

    openstack share snapshot create ${source_share_name} --name ${target_snapshot_name}


The :mod:`manila.share.drivers.vastdata.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.vastdata.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
