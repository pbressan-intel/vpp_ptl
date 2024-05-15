/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_l4fw_h__
#define __included_l4fw_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include "policy_engine/l4fw_policy_engine.h"
#include "ct/l4fw_ct.h"
#include "app_id/l4fw_app_id.h"
#include "elog_l4fw.h"

#define L4FW_WRN(...) \
    vlib_log_warn (l4fw_main.logger, __VA_ARGS__);
#define L4FW_DBG(...) \
    vlib_log_debug (l4fw_main.logger, __VA_ARGS__);

typedef enum
{
  L4FW_FEATURE_CT = 0,
  L4FW_FEATURE_APP_ID,
  L4FW_FEATURE_SF_FILTER,
  L4FW_FEATURE_COUNTERS,
  L4FW_FEATURE_PRINT_MATCH,
  L4FW_NUM_FEATURES,
} l4fw_feature_t;

static const char *l4fw_feature_strings[] = { "ct", "app_id", "sf_filter",
					      "counters", "print_match" };

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vnet_main_t * vnet_main;

    // Logging.
    vlib_log_class_t logger;

    // Counters.
    vlib_simple_counter_main_t ct_conn_counter;

    // Enable/disable features.
    bool features_enabled[L4FW_NUM_FEATURES];

    l4fw_policy_engine_context_t *engine_ctx;
} l4fw_main_t;

extern l4fw_main_t l4fw_main;

extern vlib_node_registration_t l4fw_node;

#define L4FW_PLUGIN_BUILD_VER "1.0"

#include "l4fw_types.h"

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                        L4FW HOOK POINTS
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

extern l4fw_meta_t l4fw_meta;

/**
 * @brief Next nodes of hook point: "net-in".
 */
typedef enum
{
  L4FW_NEXT_DROP,
  L4FW_N_NEXT,
} l4fw_hook_point_net_in_next_t;

l4fw_hook_point_net_in_next_t l4fw_hook_point_net_in(void *pkt_meta_buff, l4fw_meta_t *l4fw_meta_ptr);

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#endif /* __included_l4fw_h__ */