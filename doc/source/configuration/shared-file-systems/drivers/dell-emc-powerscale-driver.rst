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

Restrictions
~~~~~~~~~~~~

The PowerScale driver has the following restrictions:

-  Only IP access type is supported for NFS and CIFS.

-  Only FLAT network is supported.

-  Quotas are not yet supported.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-emc.inc
