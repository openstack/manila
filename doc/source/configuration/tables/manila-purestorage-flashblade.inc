.. _manila-purestorage-flashblade:

.. list-table:: Description of Pure Storage FlashBlade share driver configuration options
   :header-rows: 1
   :class: config-ref-table

   * - Configuration option = Default value
     - Description
   * - **[DEFAULT]**
     -
   * - ``flashblade_mgmt_vip`` = ``None``
     - (String) The name (or IP address) for the Pure Storage FlashBlade storage system management port.
   * - ``flashblade_data_vip`` = ``None``
     - (String) The name (or IP address) for the Pure Storage FlashBlade storage system data port.
   * - ``flashblade_api`` = ``None``
     - (String) API token for an administrative level user account.
   * - ``flashblade_eradicate`` = ``True``
     - (Boolean) Enable or disable filesystem and snapshot eradication on delete.
