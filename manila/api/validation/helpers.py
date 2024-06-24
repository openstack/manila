# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import pathlib

import yaml

_PARAMETERS_YAML = None


def _load_parameters():
    global _PARAMETERS_YAML

    p = pathlib.Path(__file__).with_name('parameters.yaml')
    with p.open('r') as f:
        _PARAMETERS_YAML = yaml.safe_load(f)


def description(parameter):
    if _PARAMETERS_YAML is None:
        _load_parameters()

    return _PARAMETERS_YAML[parameter]['description']
