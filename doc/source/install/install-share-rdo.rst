.. _share-node-install-rdo:

Install and configure a share node running Red Hat Enterprise Linux and CentOS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure a share node for the
Shared File Systems service. For simplicity, this configuration references one
storage node with the generic driver managing the share servers. The
generic backend manages share servers using compute, networking and block
services for provisioning shares.

Note that installation and configuration vary by distribution. This section
describes the instructions for a share node running Red Hat Enterprise Linux
or CentOS.

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # yum install openstack-manila-share python2-PyMySQL

#. Edit the ``/etc/manila/manila.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql://manila:MANILA_DBPASS@controller/manila


     Replace ``MANILA_DBPASS`` with the password you chose for
     the Shared File Systems database.

.. include:: common/share-node-common-configuration.rst

Two driver modes
----------------

.. include:: common/share-node-share-server-modes.rst

Choose one of the following options to configure the share driver:

.. include:: common/dhss-false-mode-intro.rst

Prerequisites
-------------

.. note::

   Perform these steps on the storage node.

#. Install the supporting utility packages:

   * Install LVM and NFS server packages:

     .. code-block:: console

        # yum install lvm2 nfs-utils nfs4-acl-tools portmap targetcli

   * Start the LVM metadata service and configure it to start when the
     system boots:

     .. code-block:: console

        # systemctl enable lvm2-lvmetad.service target.service
        # systemctl start lvm2-lvmetad.service target.service

.. include:: common/dhss-false-mode-configuration.rst

.. include:: common/dhss-true-mode-intro.rst

Prerequisites
-------------

Before you proceed, verify operation of the Compute, Networking, and Block
Storage services. This options requires implementation of Networking option 2
and requires installation of some Networking service components on the storage
node.

* Install the Networking service components:

  .. code-block:: console

     # yum install openstack-neutron openstack-neutron-linuxbridge ebtables

.. include:: common/dhss-true-mode-configuration.rst

Finalize installation
---------------------
#. Prepare manila-share as start/stop service. Start the Shared File Systems
   service including its dependencies and configure them to start when the
   system boots:

   .. code-block:: console

      # systemctl enable openstack-manila-share.service
      # systemctl start openstack-manila-share.service
