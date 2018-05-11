Configure components
--------------------

#. Edit the ``/etc/manila/manila.conf`` file and complete the following
   actions:

   * In the ``[DEFAULT]`` section, enable the generic driver and the NFS
     protocol:

     .. code-block:: ini

        [DEFAULT]
        ...
        enabled_share_backends = generic
        enabled_share_protocols = NFS

     .. note::

        Back end names are arbitrary. As an example, this guide uses the name
        of the driver.

   * In the ``[neutron]``, ``[nova]``, and ``[cinder]`` sections, enable
     authentication for those services:

     .. code-block:: ini

        [neutron]
        ...
        url = http://controller:9696
        auth_uri = http://controller:5000
        auth_url = http://controller:5000
        memcached_servers = controller:11211
        auth_type = password
        project_domain_name = default
        user_domain_name = default
        region_name = RegionOne
        project_name = service
        username = neutron
        password = NEUTRON_PASS

        [nova]
        ...
        auth_uri = http://controller:5000
        auth_url = http://controller:5000
        memcached_servers = controller:11211
        auth_type = password
        project_domain_name = default
        user_domain_name = default
        region_name = RegionOne
        project_name = service
        username = nova
        password = NOVA_PASS

        [cinder]
        ...
        auth_uri = http://controller:5000
        auth_url = http://controller:5000
        memcached_servers = controller:11211
        auth_type = password
        project_domain_name = default
        user_domain_name = default
        region_name = RegionOne
        project_name = service
        username = cinder
        password = CINDER_PASS

   * In the ``[generic]`` section, configure the generic driver:

     .. code-block:: ini

        [generic]
        share_backend_name = GENERIC
        share_driver = manila.share.drivers.generic.GenericShareDriver
        driver_handles_share_servers = True
        service_instance_flavor_id = 100
        service_image_name = manila-service-image
        service_instance_user = manila
        service_instance_password = manila
        interface_driver = manila.network.linux.interface.BridgeInterfaceDriver

     .. note::

        You can also use SSH keys instead of password authentication for
        service instance credentials.

     .. important::

        The ``service_image_name``, ``service_instance_flavor_id``,
        ``service_instance_user`` and ``service_instance_password`` are with
        reference to the service image that is used by the driver to create
        share servers. A sample service image for use with the ``generic``
        driver is available in the ``manila-image-elements`` project. Its
        creation is explained in the post installation steps (See:
        :ref:`post-install`).
