Shared File Systems Option 2: Driver support for share servers management
-------------------------------------------------------------------------

For simplicity, this configuration references the same storage node
as the one used for the Block Storage service.

.. note::

   This guide describes how to configure the Shared File Systems service to
   use the ``generic`` driver with the driver handles share server mode
   (DHSS) enabled. This driver requires Compute service (nova), Image service
   (glance) and Networking service (neutron) for creating and managing share
   servers; and Block storage service (cinder) for creating shares. The
   information used for creating share servers is configured as share
   networks. Generic driver with DHSS enabled also requires the tenant's
   private network (where the compute instances are running) to be attached
   to a public router.

