=========================================
Shared File Systems Installation Tutorial
=========================================

.. toctree::
   :maxdepth: 2

   get-started-with-shared-file-systems.rst
   install-controller-node.rst
   install-share-node.rst
   verify.rst
   post-install.rst
   next-steps.rst


The OpenStack Shared File Systems service (manila) provides coordinated
access to shared or distributed file systems. The method in which the share is
provisioned and consumed is determined by the Shared File Systems driver, or
drivers in the case of a multi-backend configuration. There are a variety of
drivers that support NFS, CIFS, HDFS, GlusterFS, CEPHFS and other protocols
as well.

The Shared File Systems API and scheduler services typically run on the
controller nodes. Depending upon the drivers used, the share service can run
on controllers, compute nodes, or storage nodes.

.. important::

    For simplicity, this guide describes configuring the Shared File Systems
    service to use the ``generic`` back end with the driver handles
    share server mode (DHSS) enabled that uses the `Compute service`
    (`nova`), `Networking service` (`neutron`) and `Block storage service`
    (`cinder`).

    Networking service configuration requires the capability of networks being
    attached to a public router in order to create share networks.

    Before you proceed, ensure that Compute, Networking and Block storage
    services are properly working. For networking service, ensure that option
    2 is properly configured.

For more information, see the `Configuration Reference
<http://docs.openstack.org/mitaka/config-reference/shared-file-systems.html>`_.

This chapter assumes a working setup of OpenStack following the `OpenStack
Installation Tutorial <http://docs.openstack.org/#install-guides>`_
