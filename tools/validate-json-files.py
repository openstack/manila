#!/usr/bin/env python
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json
import os
import sys

if len(sys.argv) < 2:
    print("Usage: %s <directory>" % sys.argv[0])
    sys.exit(1)

directory = sys.argv[1]

invalid_json_files = []

print("Validating JSON files in directory: ", directory)
for dirpath, dirname, files in os.walk(directory):
    json_files = [f for f in files if f.endswith('.json')]
    for json_file in json_files:
        path = os.path.join(dirpath, json_file)
        with open(path) as json_file_content:
            try:
                content = json.load(json_file_content)
            except ValueError as e:
                print("File %s has invalid JSON: %s" % (path, e))
                invalid_json_files.append(path)

if invalid_json_files:
    print("%d JSON files are invalid." % len(invalid_json_files))
    sys.exit(1)
else:
    print("All JSON files are valid.")
