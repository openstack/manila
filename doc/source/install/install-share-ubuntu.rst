.. _share-node-install-ubuntu:

Install and configure a share node running Ubuntu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure a share node for the
Shared File Systems service. For simplicity, this configuration references one
storage node with the generic driver managing the share servers. The
generic backend manages share servers using compute, networking and block
services for provisioning shares.

Note that installation and configuration vary by distribution. This section
describes the instructions for a share node running Ubuntu.

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # apt-get install manila-share python-pymysql

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

        # apt-get install lvm2 nfs-kernel-server

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

     # apt-get install neutron-plugin-linuxbridge-agent

.. include:: common/dhss-true-mode-configuration.rst

Finalize installation
---------------------
#. Prepare manila-share as start/stop service. Start the Shared File Systems
   service including its dependencies:

   .. code-block:: console

      # service manila-share restart

#. By default, the Ubuntu packages create an SQLite database. Because this
   configuration uses an SQL database server, remove the SQLite database
   file:

   .. code-block:: console

      # rm -f /var/lib/manila/manila.sqlite
