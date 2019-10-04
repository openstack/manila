.. note::
   Since API version 2.51, a share network is allowed to span multiple subnets
   and the fields ``neutron_net_id``, ``neutron_subnet_id``, ``network_type``,
   ``cidr``, ``ip_version``, ``gateway``, ``segmentation_id`` and ``mtu`` were
   moved from the share network to the subnet. The response will look like the
   below example.
