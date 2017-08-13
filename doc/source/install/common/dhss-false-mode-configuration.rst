2. Create the LVM physical volume ``/dev/sdc``:

   .. code-block:: console

      # pvcreate /dev/sdc
      Physical volume "/dev/sdc" successfully created

#. Create the LVM volume group ``manila-volumes``:

   .. code-block:: console

      # vgcreate manila-volumes /dev/sdc
      Volume group "manila-volumes" successfully created

   The Shared File Systems service creates logical volumes in this volume
   group.

#. Only instances can access Shared File Systems service volumes. However,
   the underlying operating system manages the devices associated with
   the volumes. By default, the LVM volume scanning tool scans the
   ``/dev`` directory for block storage devices that
   contain volumes. If projects use LVM on their volumes, the scanning
   tool detects these volumes and attempts to cache them which can cause
   a variety of problems with both the underlying operating system
   and project volumes. You must reconfigure LVM to scan only the devices
   that contain the ``cinder-volume`` and ``manila-volumes`` volume groups.
   Edit the ``/etc/lvm/lvm.conf`` file and complete the following actions:

   * In the ``devices`` section, add a filter that accepts the
     ``/dev/sdb`` and ``/dev/sdc`` devices and rejects all other devices:

     .. code-block:: ini

        devices {
        ...
        filter = [ "a/sdb/", "a/sdc", "r/.*/"]

     .. warning::

        If your storage nodes use LVM on the operating system disk, you
        must also add the associated device to the filter. For example,
        if the ``/dev/sda`` device contains the operating system:

        .. code-block:: ini

           filter = [ "a/sda/", "a/sdb/", "a/sdc", "r/.*/"]

        Similarly, if your compute nodes use LVM on the operating
        system disk, you must also modify the filter in the
        ``/etc/lvm/lvm.conf`` file on those nodes to include only
        the operating system disk. For example, if the ``/dev/sda``
        device contains the operating system:

        .. code-block:: ini

           filter = [ "a/sda/", "r/.*/"]

Configure components
--------------------

#. Edit the ``/etc/manila/manila.conf`` file and complete the following
   actions:

   * In the ``[DEFAULT]`` section, enable the LVM driver and the NFS
     protocol:

     .. code-block:: ini

        [DEFAULT]
        ...
        enabled_share_backends = lvm
        enabled_share_protocols = NFS

     .. note::

        Back end names are arbitrary. As an example, this guide uses the name
        of the driver.

   * In the ``[lvm]`` section, configure the LVM driver:

     .. code-block:: ini

        [lvm]
        share_backend_name = LVM
        share_driver = manila.share.drivers.lvm.LVMShareDriver
        driver_handles_share_servers = False
        lvm_share_volume_group = manila-volumes
        lvm_share_export_ip = MANAGEMENT_INTERFACE_IP_ADDRESS

     Replace ``MANAGEMENT_INTERFACE_IP_ADDRESS`` with the IP address
     of the management network interface on your storage node,
     typically 10.0.0.41 for the first node in the example architecture
     shown below:

     .. figure:: figures/hwreqs.png
        :alt: Hardware requirements

        **Hardware requirements**.
