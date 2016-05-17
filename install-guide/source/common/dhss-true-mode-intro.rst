Shared File Systems Option 2: Driver support for share servers management
-------------------------------------------------------------------------

For simplicity, this configuration references the same storage node
configuration for the Block Storage service.

.. note::

   This guide describes how to configure the Shared File Systems service to
   use the ``generic`` driver with the driver handles share server mode
   (DHSS) enabled. This mode requires Compute (nova), Networking (neutron) and
   Block storage (cinder) services for managing share servers. The information
   used for creating share servers is configured as share networks. Generic
   driver with DHSS enabled also requires network to be attached to a public
   router.