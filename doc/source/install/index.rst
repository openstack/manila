=====================
Installation Tutorial
=====================

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
drivers that support NFS, CIFS, HDFS, GlusterFS, CEPHFS, MAPRFS and other
protocols as well.

The Shared File Systems API and scheduler services typically run on the
controller nodes. Depending upon the drivers used, the share service can run
on controllers, compute nodes, or storage nodes.

.. important::

    For simplicity, this guide describes configuring the Shared File Systems
    service to use one of either:

    * the ``generic`` back end with the ``driver_handles_share_servers`` mode
      (DHSS) enabled that uses the `Compute service` (`nova`),
      `Image service` (`glance`), `Networking service` (`neutron`) and
      `Block storage service` (`cinder`); or,
    * the ``LVM`` back end with ``driver_handles_share_servers`` mode (DHSS)
      disabled.

    The storage protocol used and referenced in this guide is ``NFS``. As
    stated above, the Shared File System service supports different storage
    protocols depending on the back end chosen.

    For the ``generic`` back end, networking service configuration requires
    the capability of networks being attached to a public router in order to
    create share networks. If using this back end, ensure that Compute,
    Networking and Block storage services are properly working before you
    proceed. For networking service, ensure that option 2 (deploying the
    networking service with support for self-service networks) is properly
    configured.

    This installation tutorial also assumes that installation and configuration
    of OpenStack packages, Network Time Protocol, database engine and
    message queue has been completed as per the instructions in the `OpenStack
    Installation Tutorial. <https://docs.openstack.org/manila/latest/install/index.html>`_.
    The `Identity Service` (`keystone`) has to be pre-configured with suggested
    client environment scripts.

For more information on various Shared File Systems storage back ends,
see the `Shared File Systems Configuration Reference.
<https://docs.openstack.org/manila/latest/configuration/shared-file-systems/overview.html>`_.

To learn more about installation dependencies noted above, see the `OpenStack
Installation Tutorial. <https://docs.openstack.org/manila/latest/install/index.html>`_
