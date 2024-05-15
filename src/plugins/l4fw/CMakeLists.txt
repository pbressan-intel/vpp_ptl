# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# include_directories(${CMAKE_SOURCE_DIR})
# include_directories(${CMAKE_BINARY_DIR})

add_vpp_plugin(l4fw
  SOURCES
  net_in_node.c
  l4fw.c
  policy_engine/l4fw_policy_engine.c
  l4fw_utils.c
  app_id/l4fw_app_id.c
  ct/l4fw_ct.c
  ct/l4fw_ct_internal.c
  ct/l4fw_ct_cli.c

  MULTIARCH_SOURCES
  net_in_node.c

  API_FILES
  l4fw.api

  COMPONENT vpp-plugin-l4fw
)
