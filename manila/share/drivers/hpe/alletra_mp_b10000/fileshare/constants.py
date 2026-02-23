# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# BE Filesystem Size Limits
BE_MAX_FILESYSTEM_SIZE_GiB = 65536  # 64 TiB in GB
BE_MIN_FILESYSTEM_SIZE_GiB = 1

# BE Filesystem Expand Limits
BE_MIN_FILESYSTEM_EXPAND_SIZE_MiB = 256  # Minimum expand

# BE Filesystem Naming
BE_FILESYSTEM_NAME = "manilafs-%s"
BE_SHARESETTING_NAME = "manilass-%s"

# BE Default Block All IPs Access Rule
DEFAULT_IP_1 = "0.0.0.0"
DEFAULT_ACCESS_LEVEL_1 = "ro"
DEFAULT_SQUASH_OPTION_1 = "root_squash"
BE_DEFAULT_CLIENT_INFO_LIST = [
    {
        "ipaddress": DEFAULT_IP_1,
        "access": DEFAULT_ACCESS_LEVEL_1,
        "options": DEFAULT_SQUASH_OPTION_1
    }
]
