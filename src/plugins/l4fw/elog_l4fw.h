#ifndef __included_elog_l4fw_h__
#define __included_elog_l4fw_h__

#include <vppinfra/elog.h>

// Adapted from plugins/acl/fa_node.h.
#define elog_l4fw_X2(l4fw_elog_trace_format_label, l4fw_elog_trace_format_args,                                     \
                                                                            l4fw_elog_val1, l4fw_elog_val2)         \
do {                                                                                                                \
  CLIB_UNUSED(struct { u8 available_space[18 - sizeof(l4fw_elog_val1) - sizeof(l4fw_elog_val2)]; } *static_check);  \
  u16 thread_index = os_get_thread_index ();                                                                        \
  vlib_worker_thread_t * w = vlib_worker_threads + thread_index;                                                    \
  ELOG_TYPE_DECLARE (e) =                                                                                           \
    {                                                                                                               \
      .format = "[%02d] " l4fw_elog_trace_format_label,                                                             \
      .format_args = "i2" l4fw_elog_trace_format_args,                                                              \
    };                                                                                                              \
  CLIB_PACKED(struct                                                                                                \
    {                                                                                                               \
      u16 thread;                                                                                                   \
      typeof(l4fw_elog_val1) val1;                                                                                  \
      typeof(l4fw_elog_val2) val2;                                                                                  \
    }) *ed;                                                                                                         \
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);                                             \
  ed->thread = thread_index;                                                                                        \
  ed->val1 = l4fw_elog_val1;                                                                                        \
  ed->val2 = l4fw_elog_val2;                                                                                        \
} while (0)

#endif /* __included_elog_l4fw_h__ */