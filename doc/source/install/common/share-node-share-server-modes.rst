The share node can support two modes, with and without the handling of
share servers. The mode depends on driver support.

Option 1
--------
Deploying the service without driver support for share server management.
In this mode, the service does not do anything related to networking. The
operator must ensure network connectivity between instances and the NAS
protocol based server.

This tutorial demonstrates setting up the LVM driver which creates LVM volumes
on the share node and exports them with the help of an NFS server that is
installed locally on the share node. It therefore requires LVM and NFS packages
as well as an additional disk for the ``manila-share`` LVM volume group.

This driver mode may be referred to as ``driver_handles_share_servers = False``
mode, or simply ``DHSS=False`` mode.

Option 2
--------
Deploying the service with driver support for share server management. In
this mode, the service runs with a back end driver that creates and manages
share servers. This tutorial demonstrates setting up the ``Generic`` driver.
This driver requires Compute service (nova), Image service (glance) and
Networking service (neutron) for creating and managing share servers; and
Block storage service (cinder) for creating shares.

The information used for creating share servers is configured with the help of
share networks.

This driver mode may be referred to as ``driver_handles_share_servers = True``
mode, or simply ``DHSS=True`` mode.

.. warning::

   When running the generic driver in ``DHSS=True`` driver mode, the share
   service should be run on the same node as the networking service.
   However, such a service may not be able to run the LVM driver that runs
   in ``DHSS=False`` driver mode effectively, due to a bug in some
   distributions of Linux. For more information, see LVM Driver section in the
   `Configuration Reference Guide
   <https://docs.openstack.org/manila/latest/configuration/shared-file-systems/overview.html>`_.
