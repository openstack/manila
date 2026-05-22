.. _verify:

Verify operation
~~~~~~~~~~~~~~~~

Verify operation of the Shared File Systems service.

.. note::

   Perform these commands on the controller node.

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc.sh

#. List service components to verify successful launch of each process:

   .. code-block:: console

      $ openstack share service list
      +----+------------------+----------------+------+---------+-------+----------------------------+-----------------+
      | ID | Binary           | Host           | Zone | Status  | State | Updated At                 | Disabled Reason |
      +----+------------------+----------------+------+---------+-------+----------------------------+-----------------+
      |  1 | manila-scheduler | controller     | nova | enabled | up    | 2026-03-31T19:30:54.000000 | None            |
      |  2 | manila-share     | share1@generic | nova | enabled | up    | 2026-03-31T19:30:57.000000 | None            |
      +----+------------------+----------------+------+---------+-------+----------------------------+-----------------+
