====================================
Vastdata Share Driver
====================================

Vastdata can be used as a storage back end for the OpenStack Shared
File System service. Shares in the Shared File System service are
mapped 1:1 to Vastdata volumes. Access is provided via NFS protocol
and IP-based authentication. The `Vastdata <https://www.vastdata.com>`__
Manila driver uses the Vastdata API service.

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

-  Deny share access.

- Extend a share.

- Shrink a share.


Requirements
~~~~~~~~~~~~

-  Trash API must be enabled on Vastdata cluster.

Driver options
~~~~~~~~~~~~~~

The following table contains the configuration options specific to the
share driver.

.. include:: ../../tables/manila-vastdata.inc


Vastdata driver configuration example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following parameters shows a sample subset of the ``manila.conf`` file,
which configures two backends and the relevant ``[DEFAULT]`` options. A real
configuration would include additional ``[DEFAULT]`` options and additional
sections that are not discussed in this document:

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
   vast_vippool_name = {vip_pool}
   vast_root_export = {root_export}


Restrictions
------------

The Vastdata driver has the following restrictions:

- Only IP access type is supported for NFS.


The :mod:`manila.share.drivers.vastdata.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.vastdata.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
