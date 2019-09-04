.. _manila-nexentastor5:

.. list-table:: Description of NexentaStor5 configuration options
   :header-rows: 1
   :class: config-ref-table

   * - Configuration option = Default value
     - Description
   * - **[DEFAULT]**
     -
   * - ``nexenta_rest_addresses`` = ``None``
     - (List) One or more comma delimited IP addresses for management communication with NexentaStor appliance.
   * - ``nexenta_rest_port`` = ``8443``
     - (Integer) Port to connect to Nexenta REST API server.
   * - ``nexenta_use_https`` = ``True``
     - (Boolean) Use HTTP secure protocol for NexentaStor management REST API connections.
   * - ``nexenta_user`` = ``admin``
     - (String) User name to connect to Nexenta SA.
   * - ``nexenta_password`` = ``None``
     - (String) Password to connect to Nexenta SA.
   * - ``nexenta_pool`` = ``pool1``
     - (String) Pool name on NexentaStor.
   * - ``nexenta_nfs`` = ``True``
     - (Boolean) Defines whether share over NFS is enabled.
   * - ``nexenta_ssl_cert_verify`` = ``False``
     - (Boolean) Defines whether the driver should check ssl cert.
   * - ``nexenta_rest_connect_timeout`` = ``30``
     - (Float) Specifies the time limit (in seconds), within which the connection to NexentaStor management REST API server must be established.
   * - ``nexenta_rest_read_timeout`` = ``300``
     - (Float) Specifies the time limit (in seconds), within which NexentaStor management REST API server must send a response.
   * - ``nexenta_rest_backoff_factor`` = ``1``
     - (Float) Specifies the backoff factor to apply between connection attempts to NexentaStor management REST API server.
   * - ``nexenta_rest_retry_count`` = ``5``
     - (Integer) Specifies the number of times to repeat NexentaStor management REST API call in case of connection errors and NexentaStor appliance EBUSY or ENOENT errors.
   * - ``nexenta_nas_host`` = ``None``
     - (Hostname) Data IP address of Nexenta storage appliance.
   * - ``nexenta_mount_point_base`` = ``$state_path/mnt``
     - (String) Base directory that contains NFS share mount points.
   * - ``nexenta_share_name_prefix`` = ``share-``
     - (String) Nexenta share name prefix.
   * - ``nexenta_folder`` = ``folder``
     - (String) Parent folder on NexentaStor.
   * - ``nexenta_dataset_compression`` = ``on``
     - (String) Compression value for new ZFS folders.
   * - ``nexenta_thin_provisioning`` = ``True``
     - (Boolean) If True shares will not be space guaranteed and overprovisioning will be enabled.
   * - ``nexenta_dataset_record_size`` = ``131072``
     - (Integer) Specifies a suggested block size in for files in a file system. (bytes)
