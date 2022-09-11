.. _manila-infinidat:

.. list-table:: Description of INFINIDAT InfiniBox share driver configuration options
   :header-rows: 1
   :class: config-ref-table

   * - Configuration option = Default value
     - Description
   * - **[DEFAULT]**
     -
   * - ``infinibox_hostname`` = ``None``
     - (String) The name (or IP address) for the INFINIDAT Infinibox storage system.
   * - ``infinidat_use_ssl`` = ``False``
     - (Boolean) Enable SSL communication to access the INFINIDAT Infinibox storage system.
   * - ``infinidat_suppress_ssl_warnings`` = ``False``
     - (Boolean) Suppress requests library SSL certificate warnings.
   * - ``infinibox_login`` = ``None``
     - (String) Administrative user account name used to access the INFINIDAT Infinibox storage system.
   * - ``infinibox_password`` = ``None``
     - (String) Password for the administrative user account specified in the infinibox_login option.
   * - ``infinidat_pool_name`` = ``None``
     - (String) Name of the pool from which volumes are allocated.
   * - ``infinidat_nas_network_space_name`` = ``None``
     - (String) Name of the NAS network space on the INFINIDAT InfiniBox.
   * - ``infinidat_thin_provision`` = ``True``
     - (Boolean) Use thin provisioning
