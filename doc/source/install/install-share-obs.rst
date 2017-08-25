.. _share-node-install-obs:

Install and configure a share node running openSUSE and SUSE Linux Enterprise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure a share node for the
Shared File Systems service.

Note that installation and configuration vary by distribution. This section
describes the instructions for a share node running openSUSE and SUSE Linux
Enterprise.

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # zypper install openstack-manila-share python-PyMySQL

#. Edit the ``/etc/manila/manila.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://manila:MANILA_DBPASS@controller/manila

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

        # zypper install lvm2 nfs-kernel-server

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

     # zypper install --no-recommends openstack-neutron-linuxbridge-agent

.. include:: common/dhss-true-mode-configuration.rst

Finalize installation
---------------------
#. Prepare manila-share as start/stop service. Start the Shared File Systems
   service including its dependencies and configure them to start when the
   system boots:

   .. code-block:: console

      # systemctl enable openstack-manila-share.service tgtd.service
      # systemctl start openstack-manila-share.service tgtd.service
