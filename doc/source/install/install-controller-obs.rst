.. _manila-controller-obs:

Install and configure controller node on openSUSE and SUSE Linux Enterprise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the Shared File Systems
service, code-named manila, on the controller node that runs openSUSE and SUSE
Linux Enterprise. This service requires at least one additional share node
that manages file storage back ends.

.. include:: common/controller-node-prerequisites.rst

Install and configure components
--------------------------------

#. Install the packages:

   .. code-block:: console

      # zypper install openstack-manila-api openstack-manila-scheduler python-manilaclient

#. Edit the ``/etc/manila/manila.conf`` file and complete the
   following actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://manila:MANILA_DBPASS@controller/manila

     Replace ``MANILA_DBPASS`` with the password you chose for the Shared
     File Systems database.

.. include:: common/controller-node-common-configuration.rst

Finalize installation
---------------------

#. Start the Shared File Systems services and configure them to start when
   the system boots:

   .. code-block:: console

      # systemctl enable openstack-manila-api.service openstack-manila-scheduler.service
      # systemctl start openstack-manila-api.service openstack-manila-scheduler.service
