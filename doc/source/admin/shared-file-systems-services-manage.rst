.. _shared_file_systems_services_manage.rst:

======================
Manage shares services
======================

The Shared File Systems service provides API that allows to manage running
share services (`Share services API
<https://docs.openstack.org/api-ref/shared-file-system/>`_).
Using the :command:`manila service-list` command, it is possible to get a list
of all kinds of running services. To select only share services, you can pick
items that have field ``binary`` equal to ``manila-share``. Also, you can
enable or disable share services using raw API requests. Disabling means that
share services are excluded from the scheduler cycle and new shares will not
be placed on the disabled back end. However, shares from this service stay
available. With 2024.2 release, admin can schedule share on disabled back end
using ``only_host`` scheduler hint.


Recalculating the shares' export location
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Until the 2024.2 release, recalculating a share's export location required
restarting the corresponding manila-share manager service. This action
triggered the backend driver's "ensure shares" operation, which would execute
a series of steps to update the export locations.

Starting with the 2024.2 release, as an administrator, you can initiate export
location recalculation without restarting the manila-share service. This can
now be done directly through the "ensure shares" API.

It is possible to start the ensure shares procedure even if a service is
already running it.

To start ensure shares on a given manila-share binary, run the
:command:`openstack share service ensure shares` command:

.. code-block:: console

   $ openstack share service ensure shares <host>

.. note::

   When this command is issued, the ``manila-share`` manager will by default
   change the status of the shares to ``ensuring``, unless the
   :ref:`common configuration option <manila-common>` named
   ``update_shares_status_on_ensure`` is changed to ``False``.

.. note::

   The service will have its ``ensuring`` field set to ``True`` while this
   operation is still in progress.
