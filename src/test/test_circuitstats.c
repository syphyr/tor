/* Copyright (c) 2017-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITBUILD_PRIVATE
#define CIRCUITSTATS_PRIVATE
#define CIRCUITLIST_PRIVATE
#define STATEFILE_PRIVATE
#define CONTROL_EVENTS_PRIVATE
#define CHANNEL_FILE_PRIVATE

#include "core/or/or.h"
#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"
#include "app/config/config.h"
#include "app/config/statefile.h"
#include "app/config/or_state_st.h"
#include "app/config/or_options_st.h"
#include "feature/control/control_events.h"
#include "lib/encoding/confline.h"
#include "lib/confmgt/confmgt.h"
#include "lib/fs/dir.h"
#include "lib/fs/files.h"
#include <math.h>
#include "core/or/circuitlist.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitstats.h"
#include "core/or/circuituse.h"
#include "core/or/channel.h"
#include "core/or/relay.h"

#include "core/or/cpath_build_state_st.h"
#include "feature/hs/hs_ident.h"
#include "core/or/crypt_path_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/extendinfo.h"
#include "core/or/origin_circuit_st.h"

static origin_circuit_t *add_opened_threehop(void);
static origin_circuit_t *build_unopened_fourhop(struct timeval);
static origin_circuit_t *subtest_fourhop_circuit(struct timeval, int);

static int marked_for_close;
/* Mock function because we are not trying to test the close circuit that does
 * an awful lot of checks on the circuit object. */
static void
mock_circuit_mark_for_close(circuit_t *circ, int reason, int line,
                            const char *file)
{
  (void) circ;
  (void) reason;
  (void) line;
  (void) file;
  marked_for_close = 1;
  return;
}

static origin_circuit_t *
add_opened_threehop(void)
{
  struct timeval circ_start_time;
  memset(&circ_start_time, 0, sizeof(circ_start_time));
  extend_info_t fakehop;
  memset(&fakehop, 0, sizeof(fakehop));
  extend_info_t *fakehop_list[DEFAULT_ROUTE_LEN] = {&fakehop,
                                                    &fakehop,
                                                    &fakehop};

  return new_test_origin_circuit(true,
                                 circ_start_time,
                                 DEFAULT_ROUTE_LEN,
                                 fakehop_list);
}

static origin_circuit_t *
build_unopened_fourhop(struct timeval circ_start_time)
{
  extend_info_t fakehop;
  memset(&fakehop, 0, sizeof(fakehop));
  extend_info_t *fakehop_list[4] = {&fakehop,
                                    &fakehop,
                                    &fakehop,
                                    &fakehop};

  return new_test_origin_circuit(false,
                                 circ_start_time,
                                 4,
                                 fakehop_list);
}

static origin_circuit_t *
subtest_fourhop_circuit(struct timeval circ_start_time, int should_timeout)
{
  origin_circuit_t *origin_circ = build_unopened_fourhop(circ_start_time);

  // Now make them open one at a time and call
  // circuit_build_times_handle_completed_hop();
  origin_circ->cpath->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(origin_circ);
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ, 0);

  origin_circ->cpath->next->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(origin_circ);
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ, 0);

  // Third hop: We should count it now.
  origin_circ->cpath->next->next->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(origin_circ);
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ,
            !should_timeout); // 1 if counted, 0 otherwise

  // Fourth hop: Don't double count
  origin_circ->cpath->next->next->next->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(origin_circ);
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ,
            !should_timeout);

 done:
  return origin_circ;
}

static void
test_circuitstats_hoplen(void *arg)
{
  /* Plan:
   *   0. Test no other opened circs (relaxed timeout)
   *   1. Check >3 hop circ building w/o timeout
   *   2. Check >3 hop circs w/ timeouts..
   */
  struct timeval circ_start_time;
  origin_circuit_t *threehop = NULL;
  origin_circuit_t *fourhop = NULL;
  (void)arg;
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);

  circuit_build_times_init(get_circuit_build_times_mutable());

  // Let's set a close_ms to 2X the initial timeout, so we can
  // test relaxed functionality (which uses the close_ms timeout)
  get_circuit_build_times_mutable()->close_ms *= 2;

  tor_gettimeofday(&circ_start_time);
  circ_start_time.tv_sec -= 119; // make us hit "relaxed" cutoff

  // Test 1: Build a fourhop circuit that should get marked
  // as relaxed and eventually counted by circuit_expire_building
  // (but not before)
  fourhop = subtest_fourhop_circuit(circ_start_time, 0);
  tt_int_op(fourhop->relaxed_timeout, OP_EQ, 0);
  tt_int_op(marked_for_close, OP_EQ, 0);
  circuit_expire_building();
  tt_int_op(marked_for_close, OP_EQ, 0);
  tt_int_op(fourhop->relaxed_timeout, OP_EQ, 1);
  TO_CIRCUIT(fourhop)->timestamp_began.tv_sec -= 119;
  circuit_expire_building();
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ, 1);
  tt_int_op(marked_for_close, OP_EQ, 1);

  circuit_free_(TO_CIRCUIT(fourhop));
  circuit_build_times_reset(get_circuit_build_times_mutable());

  // Test 2: Add a threehop circuit for non-relaxed timeouts
  threehop = add_opened_threehop();

  /* This circuit should not timeout */
  tor_gettimeofday(&circ_start_time);
  circ_start_time.tv_sec -= 59;
  fourhop = subtest_fourhop_circuit(circ_start_time, 0);
  circuit_expire_building();
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ, 1);
  tt_int_op(TO_CIRCUIT(fourhop)->purpose, OP_NE,
            CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT);

  circuit_free_((circuit_t *)fourhop);
  circuit_build_times_reset(get_circuit_build_times_mutable());

  /* Test 3: This circuit should now time out and get marked as a
   * measurement circuit, but still get counted (and counted only once)
   */
  circ_start_time.tv_sec -= 2;
  fourhop = subtest_fourhop_circuit(circ_start_time, 0);
  tt_int_op(TO_CIRCUIT(fourhop)->purpose, OP_EQ,
            CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT);
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ, 1);
  circuit_expire_building();
  tt_int_op(get_circuit_build_times()->total_build_times, OP_EQ, 1);

 done:
  UNMOCK(circuit_mark_for_close_);
  circuit_free_(TO_CIRCUIT(threehop));
  circuit_free_(TO_CIRCUIT(fourhop));
  circuit_build_times_free_timeouts(get_circuit_build_times_mutable());
}

/* A fixed clock keeps both completion and expiration order reproducible. */
static struct timeval cbt_test_now;
static void
mock_cbt_gettimeofday(struct timeval *now)
{
  *now = cbt_test_now;
}

static void
test_circuitstats_prefix_accounting(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circ = NULL, *opened = NULL;
  (void)arg;
  circuitbuild_running_unit_tests();
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  circuit_build_times_init(cbt);

  /* Fast, slow, nonlive, clock-discarded, and cannibalized prefixes,
   * with and without another usable circuit. */
  for (int have_open = 0; have_open < 2; ++have_open) {
    if (have_open)
      opened = add_opened_threehop();
    for (int variant = 0; variant < 5; ++variant) {
      struct timeval start = { 1000, 0 };
      circuit_build_times_reset(cbt);
      memset(cbt->liveness.timeouts_after_firsthop, 0,
             cbt->liveness.num_recent_circs);
      cbt->liveness.after_firsthop_idx = 0;
      cbt->liveness.nonlive_timeouts = variant == 2;
      for (int i = 0; i < CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE; ++i)
        circuit_build_times_add_time(cbt, 500);
      cbt->timeout_ms = 1000;
      cbt->close_ms = 60000;
      circ = build_unopened_fourhop(start);
    circ->has_opened = variant == 4;
    circ->cpath->state = CPATH_STATE_OPEN;
    circ->cpath->next->state = CPATH_STATE_OPEN;
    circ->cpath->next->next->state = CPATH_STATE_OPEN;
    cbt_test_now = start;
    cbt_test_now.tv_usec = 100000;
    if (variant == 1)
      cbt_test_now.tv_sec += 2;
    if (variant == 3)
      cbt_test_now.tv_sec -= 1;
    circuit_build_times_handle_completed_hop(circ);
    int expected = CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE + (variant < 2);
    tt_int_op(cbt->total_build_times, OP_EQ, expected);
    tt_int_op(cbt->num_circ_timeouts, OP_EQ, have_open && variant == 1);
    uint32_t timeouts = cbt->num_circ_timeouts;
    int recent_idx = cbt->liveness.after_firsthop_idx;
    circuit_build_times_handle_completed_hop(circ);
    tt_int_op(cbt->total_build_times, OP_EQ, expected);

    /* Leave hop four stalled. The soft timeout still relaxes or changes
     * purpose, and the hard timeout still closes, without CBT failures. */
    cbt->timeout_ms = 1000;
    cbt->close_ms = 60000;
    cbt->liveness.nonlive_timeouts = 0;
    marked_for_close = 0;

    cbt_test_now.tv_sec = 1003;
      circuit_expire_building();
      if (variant != 4)
        tt_int_op(marked_for_close, OP_EQ, 0);
      cbt_test_now.tv_sec = 1061;
      circuit_expire_building();
      circuit_expire_building();
      tt_int_op(marked_for_close, OP_EQ, 1);
      tt_int_op(cbt->total_build_times, OP_EQ, expected);
      tt_int_op(cbt->num_circ_timeouts, OP_EQ, timeouts);
      tt_int_op(cbt->num_circ_closed, OP_EQ, 0);
      tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, recent_idx);
      circuit_free_(TO_CIRCUIT(circ));
      circ = NULL;
    }
    circuit_free_(TO_CIRCUIT(opened));
    opened = NULL;
  }
 done:
  circuit_free_(TO_CIRCUIT(circ));
  circuit_free_(TO_CIRCUIT(opened));
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(circuit_mark_for_close_);
}

static int cbt_rend_launches;
static origin_circuit_t *cbt_rend_retry;
static origin_circuit_t *
mock_cbt_rend_launch(uint8_t purpose, extend_info_t *ei, int flags)
{
  (void)ei;
  (void)flags;
  ++cbt_rend_launches;
  cbt_rend_retry = build_unopened_fourhop(cbt_test_now);
  cbt_rend_retry->base_.purpose = purpose;
  return cbt_rend_retry;
}

static void
mock_cbt_assert_circuit_ok(const circuit_t *circ)
{
  (void)circ;
}

/* Exercise real repurpose/close/free cleanup. Only the new network launch
 * and assertions about cryptographic fixture completeness are mocked. */
static void
test_circuitstats_prefix_lifecycle(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circ = NULL, *opened = NULL;
  (void)arg;
  circuitbuild_running_unit_tests();
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(assert_circuit_ok, mock_cbt_assert_circuit_ok);
  MOCK(circuit_launch_by_extend_info, mock_cbt_rend_launch);
  circuit_build_times_init(cbt);
  opened = add_opened_threehop();
  for (int kind = 0; kind < 2; ++kind) {
    struct timeval start = { 1000, 0 };
    cbt_rend_launches = 0;
    circuit_build_times_reset(cbt);
    for (int i = 0; i < CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE; ++i)
      circuit_build_times_add_time(cbt, 500);
    cbt->timeout_ms = 1000;
    cbt->close_ms = 60000;
    circ = build_unopened_fourhop(start);
    circ->base_.state = CIRCUIT_STATE_BUILDING;
    circ->base_.purpose = CIRCUIT_PURPOSE_S_CONNECT_REND;
    circ->has_opened = kind == 1;
    circ->hs_ident = tor_malloc_zero(sizeof(*circ->hs_ident));
    memset(circ->hs_ident->rendezvous_cookie, 0x42, REND_COOKIE_LEN);
    memset(circ->hs_ident->rendezvous_handshake_info, 0x43,
           sizeof(circ->hs_ident->rendezvous_handshake_info));
    circ->build_state->expiry_time = time(NULL) + 30;
    circ->cpath->state = CPATH_STATE_OPEN;
    circ->cpath->next->state = CPATH_STATE_OPEN;
    circ->cpath->next->next->state = CPATH_STATE_OPEN;
    cbt_test_now = start;
    cbt_test_now.tv_usec = 100000;
    circuit_build_times_handle_completed_hop(circ);
    cbt->timeout_ms = 1000;
    cbt->close_ms = 60000;
    cbt_test_now.tv_sec = 1003;
    circuit_expire_building();
    if (kind == 0) {
      tt_int_op(cbt_rend_launches, OP_EQ, 1);
      tt_int_op(cbt_rend_retry->build_state->failure_count, OP_EQ, 1);
      tt_mem_op(cbt_rend_retry->hs_ident, OP_EQ, circ->hs_ident,
                sizeof(*circ->hs_ident));
    }
    cbt_test_now.tv_sec = 1061;
    circuit_expire_building();
    tt_assert(circ->base_.marked_for_close);
    tt_int_op(cbt_rend_launches, OP_EQ, 1);
    tt_int_op(cbt->num_circ_timeouts, OP_EQ, 0);
    tt_int_op(cbt->num_circ_closed, OP_EQ, 0);
    circuit_free_(TO_CIRCUIT(circ));
    circ = NULL;
    circuit_free_(TO_CIRCUIT(cbt_rend_retry));
    cbt_rend_retry = NULL;
  }
 done:
  circuit_free_(TO_CIRCUIT(circ));
  circuit_free_(TO_CIRCUIT(opened));
  circuit_free_(TO_CIRCUIT(cbt_rend_retry));
  cbt_rend_retry = NULL;
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(assert_circuit_ok);
  UNMOCK(circuit_launch_by_extend_info);
}

static or_state_t *cbt_test_state;
static int cbt_reset_events;
static or_state_t *
mock_cbt_get_state(void)
{
  return cbt_test_state;
}

static void
mock_cbt_event(uint16_t event, char *msg)
{
  if (event == EVENT_BUILDTIMEOUT_SET && strstr(msg, "RESET"))
    ++cbt_reset_events;
  tor_free(msg);
}

static void
test_circuitstats_recovery(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  or_options_t *options = get_options_mutable();
  origin_circuit_t *old = NULL, *fresh = NULL;
  struct timeval start = { 1000, 0 };
  (void)arg;
  cbt_test_state = or_state_new();
  MOCK(get_or_state, mock_cbt_get_state);
  MOCK(queue_control_event_string, mock_cbt_event);
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  control_testing_set_global_event_mask(EVENT_MASK_(EVENT_BUILDTIMEOUT_SET));
  options->LearnCircuitBuildTimeout = 1;
  circuit_build_times_init(cbt);
  old = build_unopened_fourhop(start);
  for (int i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; ++i)
    circuit_build_times_add_time(cbt, 465);
  cbt->timeout_ms = 465;
  cbt->close_ms = 90000;
  cbt->have_computed_timeout = 1;
  for (int i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; ++i) {
    circuit_build_times_network_is_live(cbt);
    circuit_build_times_count_timeout(cbt, 0);
    tt_assert(circuit_build_times_count_close(cbt, 0, 1));
    if (i < CBT_NCIRCUITS_TO_OBSERVE - 1)
      tt_int_op(cbt->total_build_times, OP_EQ, CBT_NCIRCUITS_TO_OBSERVE);
  }
  cbt_reset_events = 0;
  setup_full_capture_of_logs(LOG_NOTICE);
  circuit_build_times_set_timeout(cbt);
  tt_int_op(cbt_reset_events, OP_EQ, 1);
  expect_log_msg_containing("restarting conservative learning");
  tt_int_op(cbt->total_build_times, OP_EQ, 0);
  tt_int_op(cbt->build_times_idx, OP_EQ, 0);
  tt_int_op(cbt->have_computed_timeout, OP_EQ, 0);
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);
  tt_double_op(fabs(cbt->timeout_ms - (60000)), OP_LT, 0.001);
  tt_double_op(fabs(cbt->close_ms - (90000)), OP_LT, 0.001);
  tt_assert(circuit_build_times_needs_circuits(cbt));
  tt_assert(old->cbt_observation_invalidated);
  mock_clean_saved_logs();
  for (int i = 0; i < 100; ++i)
    circuit_build_times_set_timeout(cbt);
  expect_no_log_entry();
  tt_int_op(cbt_reset_events, OP_EQ, 1);

  /* An old success still builds but cannot enter the repaired population. */
  cbt_test_now = start;
  cbt_test_now.tv_usec = 100000;
  old->cpath->state = CPATH_STATE_OPEN;
  old->cpath->next->state = CPATH_STATE_OPEN;
  old->cpath->next->next->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(old);
  tt_int_op(cbt->total_build_times, OP_EQ, 0);
  fresh = build_unopened_fourhop(start);
  tt_assert(!fresh->cbt_observation_invalidated);
  fresh->cpath->state = CPATH_STATE_OPEN;
  fresh->cpath->next->state = CPATH_STATE_OPEN;
  fresh->cpath->next->next->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(fresh);
  tt_int_op(cbt->total_build_times, OP_EQ, 1);

  /* Partial histories can keep learning, but a full sparse one recovers. */
  circuit_build_times_set_timeout(cbt);
  tt_int_op(cbt->total_build_times, OP_EQ, 1);
  for (int i = 1; i < CBT_NCIRCUITS_TO_OBSERVE; ++i)
    circuit_build_times_add_time(cbt, CBT_BUILD_ABANDONED);
  circuit_build_times_set_timeout(cbt);
  tt_int_op(cbt->total_build_times, OP_EQ, 0);
  tt_int_op(cbt_reset_events, OP_EQ, 2);
  /* An entirely abandoned history also recovers. Configured floor wins. */
  options->CircuitBuildTimeout = 120;
  circuit_build_times_add_time(cbt, CBT_BUILD_ABANDONED);
  circuit_build_times_set_timeout(cbt);
  tt_double_op(fabs(cbt->timeout_ms - (120000)), OP_LT, 0.001);
  tt_double_op(fabs(cbt->close_ms - (120000)), OP_LT, 0.001);
  tt_int_op(cbt_reset_events, OP_EQ, 3);
  for (int variant = 0; variant < 3; ++variant) {
    circuit_build_times_add_time(cbt, CBT_BUILD_ABANDONED);
    cbt->timeout_ms = variant == 0 ? (double)NAN : variant == 1 ? -1 : 180000;
    cbt->close_ms = variant == 0 ? (double)INFINITY :
                    variant == 1 ? -1 : 240000;
    circuit_build_times_set_timeout(cbt);
    tt_double_op(fabs(cbt->timeout_ms - (variant == 2 ? 180000 : 120000)),
                 OP_LT, 0.001);
    tt_double_op(fabs(cbt->close_ms - (variant == 2 ? 240000 : 120000)),
                 OP_LT, 0.001);
  }
  /* Disabled learning neither fits nor repairs observations. */
  options->LearnCircuitBuildTimeout = 0;
  circuit_build_times_add_time(cbt, CBT_BUILD_ABANDONED);
  circuit_build_times_set_timeout(cbt);
  tt_int_op(cbt->total_build_times, OP_EQ, 1);
 done:
  teardown_capture_of_logs();
  circuit_free_(TO_CIRCUIT(old));
  circuit_free_(TO_CIRCUIT(fresh));
  circuit_build_times_free_timeouts(cbt);
  or_state_free(cbt_test_state);
  UNMOCK(get_or_state);
  UNMOCK(queue_control_event_string);
  UNMOCK(tor_gettimeofday);
}

static void
test_circuitstats_recovery_mixed(void *arg)
{
  circuit_build_times_t cbt = {0}, loaded = {0};
  or_state_t *state = or_state_new();
  const int mincircs = CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE;
  const struct {
    int usable;
    int total;
    int recover;
  } cases[] = {
    { mincircs - 1, CBT_NCIRCUITS_TO_OBSERVE - 1, 0 },
    { mincircs - 1, CBT_NCIRCUITS_TO_OBSERVE, 1 },
    { mincircs, CBT_NCIRCUITS_TO_OBSERVE, 0 },
    { 1, CBT_NCIRCUITS_TO_OBSERVE, 1 },
    { mincircs - 1, mincircs - 1, 0 },
    { mincircs, mincircs, 0 },
  };
  (void)arg;
  cbt_test_state = state;
  MOCK(get_or_state, mock_cbt_get_state);
  get_options_mutable()->LearnCircuitBuildTimeout = 1;

  for (unsigned i = 0; i < ARRAY_LENGTH(cases); ++i) {
    circuit_build_times_init(&cbt);
    for (int j = 0; j < cases[i].total; ++j)
      circuit_build_times_add_time(&cbt, j < cases[i].usable ?
                                   (build_time_t)(400 + (j % 10) * 50) :
                                   CBT_BUILD_ABANDONED);
    cbt.timeout_ms = 465;
    cbt.close_ms = 90000;
    /* Startup and runtime must apply the same recovery threshold. */
    circuit_build_times_update_state(&cbt, state);
    tt_int_op(circuit_build_times_parse_state(&loaded, state), OP_EQ, 0);
    circuit_build_times_set_timeout(&cbt);
    tt_int_op(cbt.total_build_times, OP_EQ,
              cases[i].recover ? 0 : cases[i].total);
    tt_int_op(loaded.total_build_times, OP_EQ, cbt.total_build_times);
    tt_int_op(cbt.have_computed_timeout, OP_EQ,
              !cases[i].recover && cases[i].total >= mincircs);
    tt_int_op(loaded.have_computed_timeout, OP_EQ, cbt.have_computed_timeout);
    if (cases[i].recover) {
      tt_double_op(fabs(cbt.timeout_ms - 60000), OP_LT, 0.001);
      tt_double_op(fabs(cbt.close_ms - 90000), OP_LT, 0.001);
      tt_double_op(fabs(loaded.timeout_ms - 60000), OP_LT, 0.001);
      tt_assert(circuit_build_times_needs_circuits(&cbt));
    }
    circuit_build_times_free_timeouts(&cbt);
    circuit_build_times_free_timeouts(&loaded);
  }
 done:
  circuit_build_times_free_timeouts(&cbt);
  circuit_build_times_free_timeouts(&loaded);
  or_state_free(state);
  UNMOCK(get_or_state);
}

static void
test_circuitstats_recovery_load(void *arg)
{
  circuit_build_times_t cbt;
  or_options_t *options = get_options_mutable();
  char *before = NULL, *after = NULL;
  (void)arg;
  memset(&cbt, 0, sizeof(cbt));
  cbt_test_state = or_state_new();
  MOCK(get_or_state, mock_cbt_get_state);
  options->LearnCircuitBuildTimeout = 1;
  config_line_append(&cbt_test_state->Guard, "Guard", "unchanged-guard-state");
  before = config_dump(get_state_mgr(), NULL, cbt_test_state, 1, 0);
  for (int avoid = 0; avoid < 2; ++avoid) {
    options->AvoidDiskWrites = avoid;
    cbt_test_state->TotalBuildTimes = CBT_NCIRCUITS_TO_OBSERVE;
    cbt_test_state->CircuitBuildAbandonedCount = CBT_NCIRCUITS_TO_OBSERVE;
    cbt_test_state->next_write = TIME_MAX;
    tt_int_op(circuit_build_times_parse_state(&cbt, cbt_test_state), OP_EQ, 0);
    tt_int_op(cbt.total_build_times, OP_EQ, 0);
    tt_double_op(fabs(cbt.timeout_ms - (60000)), OP_LT, 0.001);
    tt_assert(circuit_build_times_needs_circuits(&cbt));
    if (avoid) {
      tt_i64_op(cbt_test_state->next_write, OP_GE, time(NULL));
      tt_i64_op(cbt_test_state->next_write, OP_LE, time(NULL) + 3600);
    } else {
      tt_i64_op(cbt_test_state->next_write, OP_EQ, 0);
    }
    circuit_build_times_update_state(&cbt, cbt_test_state);
    after = config_dump(get_state_mgr(), NULL, cbt_test_state, 1, 0);
    tt_str_op(before, OP_EQ, after);
    tor_free(after);
    circuit_build_times_free_timeouts(&cbt);
  }
  /* Restarting in fixed mode ignores abandoned history. */
  options->LearnCircuitBuildTimeout = 0;
  options->CircuitBuildTimeout = 60;
  cbt_test_state->TotalBuildTimes = CBT_NCIRCUITS_TO_OBSERVE;
  cbt_test_state->CircuitBuildAbandonedCount = CBT_NCIRCUITS_TO_OBSERVE;
  tt_int_op(circuit_build_times_parse_state(&cbt, cbt_test_state), OP_EQ, 0);
  tt_double_op(fabs(cbt.timeout_ms - (60000)), OP_LT, 0.001);
  tt_double_op(fabs(cbt.close_ms - (60000)), OP_LT, 0.001);
  tt_int_op(cbt.total_build_times, OP_EQ, 0);
 done:
  circuit_build_times_free_timeouts(&cbt);
  or_state_free(cbt_test_state);
  tor_free(before);
  tor_free(after);
  UNMOCK(get_or_state);
}

static void
test_circuitstats_recovery_backlog(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  smartlist_t *old = smartlist_new();
  origin_circuit_t *opened = NULL;
  struct timeval start = { 1000, 0 };
  (void)arg;
  circuitbuild_running_unit_tests();
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(assert_circuit_ok, mock_cbt_assert_circuit_ok);
  circuit_build_times_init(cbt);
  setup_full_capture_of_logs(LOG_NOTICE);
  opened = add_opened_threehop();
  for (int i = 0; i < 400; ++i) {
    origin_circuit_t *circ = build_unopened_fourhop(start);
    circ->base_.state = CIRCUIT_STATE_BUILDING;
    circ->base_.purpose = CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT;
    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    smartlist_add(old, circ);
  }
  for (int i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; ++i)
    circuit_build_times_add_time(cbt, i ? CBT_BUILD_ABANDONED : 465);
  cbt->timeout_ms = 465;
  cbt->close_ms = 60000;
  cbt_test_now.tv_sec = 1061;
  cbt_test_now.tv_usec = 0;
  circuit_build_times_network_is_live(cbt);
  /* First terminal close overwrites the last completion; the rest of this
   * very same expiration pass must not refill the repaired history. */
  circuit_expire_building();
  expect_log_msg_containing("prefix_hops_0=400");
  expect_log_msg_containing("abandoned=1 excluded=399");
  tt_int_op(cbt->total_build_times, OP_EQ, 0);
  tt_int_op(cbt->num_circ_closed, OP_EQ, 0);
  SMARTLIST_FOREACH_BEGIN(old, origin_circuit_t *, circ) {
    tt_assert(circ->base_.marked_for_close);
    tt_assert(circ->cbt_observation_invalidated);
  } SMARTLIST_FOREACH_END(circ);
  tt_double_op(fabs(cbt->timeout_ms - (60000)), OP_LT, 0.001);
 done:
  teardown_capture_of_logs();  SMARTLIST_FOREACH(old, origin_circuit_t *, circ,
                    circuit_free_(TO_CIRCUIT(circ)));
  smartlist_free(old);
  circuit_free_(TO_CIRCUIT(opened));
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(assert_circuit_ok);
}

/* Use the actual installed state and file writer, including delayed writes. */
static void
test_circuitstats_recovery_statefile(void *arg)
{
  or_options_t *options = get_options_mutable();
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  char *path = NULL, *contents = NULL;
  const char *abandoned = "TotalBuildTimes 1000\n"
                          "CircuitBuildAbandonedCount 1000\n";
  (void)arg;
  tor_free(options->DataDirectory);
  options->DataDirectory = tor_strdup(get_fname("cbt-state"));
  tt_int_op(check_private_dir(options->DataDirectory, CPD_CREATE, NULL),
            OP_EQ, 0);
  path = get_datadir_fname("state");
  options->LearnCircuitBuildTimeout = 1;
  for (int avoid = 0; avoid < 2; ++avoid) {
    time_t now = time(NULL);
    options->AvoidDiskWrites = avoid;
    tt_int_op(write_str_to_file(path, abandoned, 0), OP_EQ, 0);
    tt_int_op(or_state_load(), OP_EQ, 0);
    tt_int_op(cbt->total_build_times, OP_EQ, 0);
    tt_int_op(or_state_save(now), OP_EQ, 0);
    contents = read_file_to_str(path, 0, NULL);
    tt_assert(contents);
    if (avoid) {
      /* Startup already has a write pending. Once flushed, runtime recovery
       * must schedule a delayed write without overriding earlier work. */
      circuit_build_times_add_time(cbt, CBT_BUILD_ABANDONED);
      circuit_build_times_set_timeout(cbt);
      tt_i64_op(get_or_state()->next_write, OP_GT, now);
      tt_int_op(or_state_save(now), OP_EQ, 0);
      tt_i64_op(get_or_state()->LastWritten, OP_EQ, now);
      tor_free(contents);
      tt_int_op(or_state_save(now + 3601), OP_EQ, 0);
      tt_i64_op(get_or_state()->LastWritten, OP_EQ, now + 3601);
      contents = read_file_to_str(path, 0, NULL);
      tt_assert(contents);
    }
    tt_assert(!strstr(contents, "TotalBuildTimes 1000"));
    tt_assert(!strstr(contents, "CircuitBuildAbandonedCount 1000"));
    tor_free(contents);
    circuit_build_times_free_timeouts(cbt);
    or_state_free_all();
    tt_int_op(or_state_load(), OP_EQ, 0);
    tt_int_op(cbt->total_build_times, OP_EQ, 0);
    circuit_build_times_free_timeouts(cbt);
    or_state_free_all();
  }
 done:
  circuit_build_times_free_timeouts(cbt);
  or_state_free_all();
  tor_free(contents);
  tor_free(path);
}

static void
test_circuitstats_diagnostics(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circ = NULL;
  channel_t channel;
  struct timeval start = { 1000, 0 };
  (void)arg;
  memset(&channel, 0, sizeof(channel));
  memset(&cbt_diagnostics, 0, sizeof(cbt_diagnostics));
  circuitbuild_running_unit_tests();
  circuit_build_times_init(cbt);
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  setup_full_capture_of_logs(LOG_NOTICE);
  circuit_build_times_report_diagnostics(1000);
  expect_no_log_entry();
  /* One-hop attempts were never eligible three-hop observations. */
  circ = build_unopened_fourhop(start);
  circ->build_state->desired_path_len = 1;
  circ->cbt_observation_invalidated = 1;
  circuit_build_times_count_circ_timeout(circ);
  tt_u64_op(cbt_diagnostics.excluded, OP_EQ, 0);
  circuit_free_(TO_CIRCUIT(circ));
  circ = NULL;
  for (int hops = 0; hops < 4; ++hops) {
    circ = build_unopened_fourhop(start);
    circ->base_.state = CIRCUIT_STATE_BUILDING;
    circ->global_identifier = 987654321;
    circ->base_.n_circ_id = 123456789;
    circ->hs_ident = tor_malloc_zero(sizeof(*circ->hs_ident));
    memset(circ->hs_ident, 0x5a, sizeof(*circ->hs_ident));
    strlcpy(circ->cpath->extend_info->nickname, "PrivateRelayFixture",
            sizeof(circ->cpath->extend_info->nickname));
    memset(circ->cpath->extend_info->identity_digest, 0x6b, DIGEST_LEN);
    tor_addr_parse(&circ->cpath->extend_info->orports[0].addr, "192.0.2.123");
    circ->cpath->extend_info->orports[0].port = 23456;
    circ->base_.n_chan = &channel;
    channel.state = hops % 2 ? CHANNEL_STATE_OPEN : CHANNEL_STATE_OPENING;
    crypt_path_t *hop = circ->cpath;
    for (int i = 0; i < hops; ++i, hop = hop->next)
      hop->state = CPATH_STATE_OPEN;
    /* Nonlive circuits still appear in expiry diagnostics. */
    cbt->liveness.nonlive_timeouts = 1;
    circuit_build_times_note_expiry(circ);
    circuit_build_times_note_expiry(circ);
    circ->base_.n_chan = NULL;
    circuit_free_(TO_CIRCUIT(circ));
    circ = NULL;
  }
  circuit_build_times_reset(cbt);
  tt_u64_op(cbt_diagnostics.prefix_hops[0], OP_EQ, 1);
  tt_u64_op(cbt_diagnostics.prefix_hops[1], OP_EQ, 1);
  tt_u64_op(cbt_diagnostics.prefix_hops[2], OP_EQ, 1);
  tt_u64_op(cbt_diagnostics.post_prefix, OP_EQ, 1);
  tt_u64_op(cbt_diagnostics.open_channel, OP_EQ, 2);
  tt_u64_op(cbt_diagnostics.other_channel, OP_EQ, 2);
  circuit_build_times_report_diagnostics(1000);
  /* Exact fixed vocabulary also excludes all injected identifiers and
   * individual timings, without enumerating possible encodings of them. */
  expect_single_log_msg("Circuit build expiry summary: prefix_hops_0=1 "
      "prefix_hops_1=1 prefix_hops_2=1 post_prefix=1 open_channel=2 "
      "other_channel=2 late_firsthop=0 completed=0 abandoned=0 excluded=0 "
      "adaptive=1 connection_failed=0\n");
  mock_clean_saved_logs();
  circ = build_unopened_fourhop(start);
  circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
  circuit_build_times_count_circ_timeout(circ);
  tt_u64_op(cbt->num_circ_timeouts, OP_EQ, 1);
  tt_u64_op(cbt_diagnostics.prefix_hops[0], OP_EQ, 0);
  circ->cpath->state = CPATH_STATE_OPEN;
  cbt_test_now = start;
  cbt_test_now.tv_usec = 100000;
  circuit_build_times_handle_completed_hop(circ);
  circuit_build_times_handle_completed_hop(circ);
  tt_u64_op(cbt_diagnostics.late_firsthop, OP_EQ, 1);
  tt_u64_op(cbt->num_circ_timeouts, OP_EQ, 1);
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);
  circ->cpath->next->state = CPATH_STATE_OPEN;
  circ->cpath->next->next->state = CPATH_STATE_OPEN;
  cbt->liveness.nonlive_timeouts = 0;
  circuit_build_times_handle_completed_hop(circ);
  tt_u64_op(cbt_diagnostics.completed, OP_EQ, 1);
  circuit_build_times_report_diagnostics(1300);
  expect_no_log_entry(); /* Healthy completion alone is quiet. */
  circ->cbt_observation_invalidated = 1;
  circ->cbt_prefix_measurement_done = 0;
  circ->cbt_soft_timeout_before_firsthop = 1;
  circuit_build_times_handle_completed_hop(circ);
  tt_u64_op(cbt_diagnostics.late_firsthop, OP_EQ, 1);
  circuit_build_times_note_expiry(circ);
  circuit_build_times_note_expiry(circ);
  tt_u64_op(cbt_diagnostics.excluded, OP_EQ, 1);
  circuit_build_times_report_diagnostics(1299);
  expect_no_log_entry();
  circuit_build_times_report_diagnostics(999); /* Clock moved backwards. */
  expect_no_log_entry();
  circuit_build_times_report_diagnostics(1300);
  expect_single_log_msg("late_firsthop=1 completed=1 abandoned=0 excluded=1");
  mock_clean_saved_logs();
  circuit_build_times_report_diagnostics(1600);
  expect_no_log_entry();

  cbt_diagnostics.post_prefix = UINT64_MAX;
  circ->cbt_expiry_reported = 0;
  circuit_build_times_note_expiry(circ);
  tt_u64_op(cbt_diagnostics.post_prefix, OP_EQ, UINT64_MAX);
 done:
  if (circ)
    circ->base_.n_chan = NULL;
  circuit_free_(TO_CIRCUIT(circ));
  circuit_build_times_free_timeouts(cbt);
  teardown_capture_of_logs();
  UNMOCK(tor_gettimeofday);
}

/* Stalled bootstrap: liveness permits abandonment only in the padding case,
 * but both cases must report a zero-hop terminal failure exactly once. */
static const char *
mock_cbt_describe_peer(channel_t *chan)
{
  (void)chan;
  return "192.0.2.123:23456";
}

static void
test_circuitstats_stalled_expiry(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circ = NULL;
  struct timeval start = { 1000, 0 };
  channel_t channel;
  (void)arg;
  memset(&channel, 0, sizeof(channel));
  channel.state = CHANNEL_STATE_OPEN;
  circuitbuild_running_unit_tests();
  circuit_build_times_init(cbt);
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(channel_describe_peer, mock_cbt_describe_peer);
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  setup_full_capture_of_logs(LOG_NOTICE);
  for (int live = 0; live < 2; ++live) {
    memset(&cbt_diagnostics, 0, sizeof(cbt_diagnostics));
    circuit_build_times_reset(cbt);
    for (int i = 0; i < CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE; ++i)
      circuit_build_times_add_time(cbt, 500);
    cbt->timeout_ms = 465;
    cbt->close_ms = 60000;
    cbt->liveness.nonlive_timeouts = !live;
    cbt->liveness.network_last_live = live ? 1060 : 0;
    circ = build_unopened_fourhop(start);
    circ->base_.state = CIRCUIT_STATE_BUILDING;
    circ->base_.n_chan = &channel;
    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    cbt_test_now.tv_sec = 1002;
    cbt_test_now.tv_usec = 0;
    circuit_expire_building();
    tt_assert(circ->relaxed_timeout);
    tt_u64_op(cbt_diagnostics.prefix_hops[0], OP_EQ, 0);
    cbt_test_now.tv_sec = 1061;
    circuit_expire_building(); /* Repurpose only, no terminal expiry yet. */
    tt_u64_op(cbt_diagnostics.prefix_hops[0], OP_EQ, 0);
    mock_clean_saved_logs();
    circuit_expire_building();
    expect_single_log_msg("prefix_hops_0=1 prefix_hops_1=0 prefix_hops_2=0 "
                          "post_prefix=0 open_channel=1 other_channel=0");
    if (live) {
      expect_log_msg_containing("abandoned=1");
    } else {
      expect_log_msg_containing("abandoned=0");
    }
    circ->base_.n_chan = NULL;
    circuit_free_(TO_CIRCUIT(circ));
    circ = NULL;
  }
 done:
  if (circ)
    circ->base_.n_chan = NULL;
  circuit_free_(TO_CIRCUIT(circ));
  circuit_build_times_free_timeouts(cbt);
  teardown_capture_of_logs();
  UNMOCK(tor_gettimeofday);
  UNMOCK(channel_describe_peer);
  UNMOCK(circuit_mark_for_close_);
}

static int
mock_cbt_channel_is_canonical(channel_t *chan)
{
  (void)chan;
  return 1;
}

/* Exercise channel failure notification and real close/free cleanup. */
static void
test_circuitstats_connection_failure(void *arg)
{
  origin_circuit_t *circ = NULL;
  channel_t channel;
  struct timeval start = { 1000, 0 };
  (void)arg;
  memset(&channel, 0, sizeof(channel));
  memset(channel.identity_digest, 0x42, DIGEST_LEN);
  channel.is_canonical = mock_cbt_channel_is_canonical;
  memset(&cbt_diagnostics, 0, sizeof(cbt_diagnostics));
  MOCK(assert_circuit_ok, mock_cbt_assert_circuit_ok);
  MOCK(channel_describe_peer, mock_cbt_describe_peer);
  setup_full_capture_of_logs(LOG_NOTICE);

  /* Fixed-timeout diagnostics must work without adaptive learning. */
  get_options_mutable()->LearnCircuitBuildTimeout = 0;
  for (int variant = 0; variant < 3; ++variant) {
    circ = build_unopened_fourhop(start);
    circ->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
    circ->cpath->state = CPATH_STATE_CLOSED;
    circ->base_.n_hop = extend_info_dup(circ->cpath->extend_info);
    memcpy(circ->base_.n_hop->identity_digest, channel.identity_digest,
           DIGEST_LEN);
    if (variant == 1)
      circ->build_state->desired_path_len = 1;
    circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_CHAN_WAIT);
    tt_int_op(circuit_count_pending_on_channel(&channel), OP_EQ, 1);
    if (variant == 2)
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);
    else
      circuit_n_chan_done(&channel, 0);
    tt_assert(circ->base_.marked_for_close);
    tt_int_op(circuit_count_pending_on_channel(&channel), OP_EQ, 0);
    circuit_n_chan_done(&channel, 0); /* No duplicate accounting. */
    circ = NULL;
    circuit_close_all_marked();
    tt_u64_op(cbt_diagnostics.connection_failed, OP_EQ, 1);
    tt_u64_op(cbt_diagnostics.prefix_hops[0], OP_EQ, 0);
    tt_u64_op(cbt_diagnostics.other_channel, OP_EQ, 0);
  }
  circuit_build_times_report_diagnostics(1000);
  expect_log_msg_containing("adaptive=0 connection_failed=1");
  mock_clean_saved_logs();
  cbt_diagnostics.connection_failed = 1;
  circuit_build_times_report_diagnostics(1299);
  expect_no_log_entry();
  circuit_build_times_report_diagnostics(1300);
  expect_log_msg_containing("connection_failed=1");
 done:
  circuit_free_(TO_CIRCUIT(circ));
  teardown_capture_of_logs();
  UNMOCK(assert_circuit_ok);
  UNMOCK(channel_describe_peer);
}

/* Integrate repeated HS fourth-hop failures with healthy and slow prefix
 * observations, using real expiration, repurpose, close and free paths. */
static void
test_circuitstats_mixed_rendezvous(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circ = NULL, *opened = NULL;
  (void)arg;
  circuitbuild_running_unit_tests();
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(assert_circuit_ok, mock_cbt_assert_circuit_ok);
  MOCK(circuit_launch_by_extend_info, mock_cbt_rend_launch);
  circuit_build_times_init(cbt);
  opened = add_opened_threehop();
  tt_assert(circuit_any_opened_circuits());
  for (int i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; ++i)
    circuit_build_times_add_time(cbt, 500);
  for (int i = 0; i < 200; ++i) {
    struct timeval start = { 1000 + i*100, 0 };
    cbt->timeout_ms = 1000;
    cbt->close_ms = 60000;
    circ = build_unopened_fourhop(start);
    circ->base_.purpose = CIRCUIT_PURPOSE_S_CONNECT_REND;
    circ->base_.state = CIRCUIT_STATE_BUILDING;
    circ->hs_ident = tor_malloc_zero(sizeof(*circ->hs_ident));
    circ->build_state->expiry_time = time(NULL) + 30;
    circ->cpath->state = CPATH_STATE_OPEN;
    circ->cpath->next->state = CPATH_STATE_OPEN;
    circ->cpath->next->next->state = CPATH_STATE_OPEN;
    cbt_test_now = start;
    cbt_test_now.tv_usec = 500000;
    if (i % 4 == 0)
      cbt_test_now.tv_sec += 2;
    cbt_rend_launches = 0;
    circuit_build_times_handle_completed_hop(circ);
    cbt->timeout_ms = 1000;
    cbt->close_ms = 60000;
    cbt_test_now.tv_sec = start.tv_sec + 3;
    circuit_expire_building();
    cbt_test_now.tv_sec = start.tv_sec + 61;
    circuit_expire_building();
    tt_assert(circ->base_.marked_for_close);
    tt_int_op(cbt_rend_launches, OP_EQ, 1);
    tt_int_op(cbt->total_build_times, OP_EQ, CBT_NCIRCUITS_TO_OBSERVE);
    tt_int_op(cbt->num_circ_closed, OP_EQ, 0);
    tt_int_op(cbt->num_circ_timeouts, OP_EQ, i/4 + 1);
    tt_int_op(opened->base_.state, OP_EQ, CIRCUIT_STATE_OPEN);
    tt_assert(!opened->base_.marked_for_close);
    circuit_free_(TO_CIRCUIT(circ));
    circ = NULL;
    circuit_free_(TO_CIRCUIT(cbt_rend_retry));
    cbt_rend_retry = NULL;
    tt_int_op(smartlist_len(circuit_get_global_origin_circuit_list()),
              OP_EQ, 1);
  }
 done:
  circuit_free_(TO_CIRCUIT(circ));
  circuit_free_(TO_CIRCUIT(opened));
  circuit_free_(TO_CIRCUIT(cbt_rend_retry));
  cbt_rend_retry = NULL;
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(assert_circuit_ok);
  UNMOCK(circuit_launch_by_extend_info);
}

/* Callback/expiry order must not change the number of timeout events. */
static void
test_circuitstats_late_firsthop(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circ = NULL, *opened = NULL;
  const struct timeval start = { 1000, 0 };
  (void)arg;
  get_options_mutable()->LearnCircuitBuildTimeout = 1;
  get_options_mutable()->AvoidDiskWrites = 1;
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  circuit_build_times_init(cbt);
  for (int have_open = 0; have_open < 2; ++have_open) {
    if (have_open)
      opened = add_opened_threehop();
    /* Callback first, expiration first, no response, recovery exclusion,
     * and learning disabled between the timeout and the response. */
    for (int kind = 0; kind < 5; ++kind) {
      circuit_build_times_reset(cbt);
      memset(cbt->liveness.timeouts_after_firsthop, 0,
             cbt->liveness.num_recent_circs);
      cbt->liveness.after_firsthop_idx = 0;
      for (int i = 0; i < CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE; ++i)
        circuit_build_times_add_time(cbt, 500);
      cbt->timeout_ms = 1000;
      cbt->close_ms = 60000;
      circ = build_unopened_fourhop(start);
      circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
      cbt_test_now = start;
      cbt_test_now.tv_sec += 3;
      if (kind == 0) {
        circ->cpath->state = CPATH_STATE_OPEN;
        circuit_build_times_handle_completed_hop(circ);
      }
      circuit_expire_building();
      tt_int_op(cbt->num_circ_timeouts, OP_EQ, 1);
      if (kind == 3)
        circ->cbt_observation_invalidated = 1;
      if (kind == 4)
        get_options_mutable()->LearnCircuitBuildTimeout = 0;
      if (kind != 2)
        circ->cpath->state = CPATH_STATE_OPEN;
      circuit_build_times_handle_completed_hop(circ);
      circuit_build_times_handle_completed_hop(circ);
      circuit_expire_building();
      tt_int_op(cbt->num_circ_timeouts, OP_EQ, 1);
      tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, kind < 2);
      tt_int_op(cbt->liveness.timeouts_after_firsthop[0], OP_EQ, kind < 2);
      get_options_mutable()->LearnCircuitBuildTimeout = 1;
      if (kind < 2) {
        circ->cpath->next->state = CPATH_STATE_OPEN;
        circ->cpath->next->next->state = CPATH_STATE_OPEN;
        circuit_build_times_handle_completed_hop(circ);
        tt_int_op(cbt->total_build_times, OP_EQ,
                  CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE + 1);
        tt_int_op(cbt->liveness.timeouts_after_firsthop[0], OP_EQ, 1);
        int recent_idx = cbt->liveness.after_firsthop_idx;
        circuit_build_times_handle_completed_hop(circ);
        cbt_test_now.tv_sec = 1061;
        circuit_expire_building();
        circuit_expire_building();
        tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, recent_idx);
        tt_int_op(cbt->num_circ_timeouts, OP_EQ, 1);
      }
      circuit_free_(TO_CIRCUIT(circ));
      circ = NULL;
    }
    circuit_free_(TO_CIRCUIT(opened));
    opened = NULL;
  }
 done:
  get_options_mutable()->LearnCircuitBuildTimeout = 1;
  circuit_free_(TO_CIRCUIT(circ));
  circuit_free_(TO_CIRCUIT(opened));
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(circuit_mark_for_close_);
}

/* Reset in the callback is allowed. Old short deadlines must not be replayed,
 * but genuine completion samples and later current-deadline misses survive. */
static void
test_circuitstats_late_firsthop_reset(void *arg)
{
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  origin_circuit_t *circs[40] = { NULL };
  origin_circuit_t *opened = NULL;
  const struct timeval start = { 1000, 0 };
  (void)arg;
  circuitbuild_running_unit_tests();
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  circuit_build_times_init(cbt);
  opened = add_opened_threehop();
  for (int i = 0; i < CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE; ++i)
    circuit_build_times_add_time(cbt, 500);
  cbt->timeout_ms = 1000;
  cbt->close_ms = 60000;
  cbt_test_now = start;
  cbt_test_now.tv_sec += 3;
  for (unsigned i = 0; i < ARRAY_LENGTH(circs); ++i) {
    circs[i] = build_unopened_fourhop(start);
    circs[i]->cpath->state = CPATH_STATE_AWAITING_KEYS;
  }
  circuit_expire_building();
  tt_int_op(cbt->num_circ_timeouts, OP_EQ, ARRAY_LENGTH(circs));
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);
  for (int i = 0; i < CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT; ++i) {
    circs[i]->cpath->state = CPATH_STATE_OPEN;
    circuit_build_times_handle_completed_hop(circs[i]);
  }
  tt_double_op(fabs(cbt->timeout_ms - 60000), OP_LT, 0.001);
  tt_int_op(cbt->total_build_times, OP_EQ, 0);
  tt_int_op(cbt->num_circ_timeouts, OP_EQ, 0); /* Reset clears totals. */
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);
  for (unsigned i = 0; i < ARRAY_LENGTH(circs); ++i) {
    circs[i]->cpath->state = CPATH_STATE_OPEN;
    circuit_build_times_handle_completed_hop(circs[i]);
    circuit_build_times_handle_completed_hop(circs[i]);
  }
  tt_double_op(fabs(cbt->timeout_ms - 60000), OP_LT, 0.001);
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);

  /* An old attempt finishing below the new deadline remains a real sample. */
  origin_circuit_t *success = circs[39];
  success->cpath->next->state = CPATH_STATE_OPEN;
  success->cpath->next->next->state = CPATH_STATE_OPEN;
  circuit_build_times_handle_completed_hop(success);
  tt_int_op(cbt->total_build_times, OP_EQ, 1);
  tt_int_op(cbt->circuit_build_times[0], OP_EQ, 3000);
  tt_assert(success->cbt_prefix_measurement_done);
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);

  /* No new hop callbacks: the expiry pass qualifies pending attempts when
   * they really exceed 60 seconds. Its reset to 120 seconds must apply to
   * the rest of the backlog and to this pass's physical expiry cutoffs. */
  cbt_test_now.tv_sec = 1060;
  circuit_expire_building();
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);
  cbt_test_now.tv_sec = 1061;
  marked_for_close = 0;
  circuit_expire_building();
  tt_double_op(fabs(cbt->timeout_ms - 120000), OP_LT, 0.001);
  tt_int_op(cbt->liveness.after_firsthop_idx, OP_EQ, 0);
  tt_int_op(marked_for_close, OP_EQ, 0);
  circuit_expire_building();
  tt_double_op(fabs(cbt->timeout_ms - 120000), OP_LT, 0.001);
  tt_int_op(cbt->num_circ_timeouts, OP_EQ, 0);
 done:
  for (unsigned i = 0; i < ARRAY_LENGTH(circs); ++i)
    circuit_free_(TO_CIRCUIT(circs[i]));
  circuit_free_(TO_CIRCUIT(opened));
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(circuit_mark_for_close_);
}

static int fourth_extend_result, fourth_extend_calls;
static int
mock_fourth_extend(streamid_t stream_id, circuit_t *circ, uint8_t command,
                  const char *payload, size_t len, crypt_path_t *layer,
                  const char *file, int line)
{
  (void)stream_id; (void)circ; (void)payload; (void)len;
  (void)layer; (void)file; (void)line;
  tor_assert(command == RELAY_COMMAND_EXTEND2);
  ++fourth_extend_calls;
  return fourth_extend_result;
}

static void
test_circuitstats_fresh_rend_extension(void *arg)
{
  (void)arg;
  origin_circuit_t *circ = NULL, *opened = NULL;
  circuit_build_times_t *cbt = get_circuit_build_times_mutable();
  const struct timeval start = { 1000, 0 };
  circuitbuild_running_unit_tests();
  MOCK(tor_gettimeofday, mock_cbt_gettimeofday);
  MOCK(relay_send_command_from_edge_, mock_fourth_extend);
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  circuit_build_times_init(cbt);
  opened = add_opened_threehop();
  enum { FRESH, CLIENT_INTRO, VANGUARD, MEASUREMENT, CANNIBALIZED,
         LONG_PATH, EARLIER_HOP, FIXED, SEND_FAILED, SLOW_PREFIX, N_CASES };
  for (int kind = 0; kind < N_CASES; ++kind) {
    circuit_build_times_reset(cbt);
    get_options_mutable()->LearnCircuitBuildTimeout = kind != FIXED;
    get_options_mutable()->CircuitBuildTimeout = kind == FIXED ? 60 : 0;
    cbt->timeout_ms = cbt->close_ms = 60000;
    cbt->liveness.nonlive_timeouts = 0;
    cbt->liveness.network_last_live = 1005;
    circ = build_unopened_fourhop(start);
    circ->base_.state = CIRCUIT_STATE_BUILDING;
    circ->base_.purpose = CIRCUIT_PURPOSE_S_CONNECT_REND;
    circ->build_state->expiry_time = 1030;
    if (kind == CLIENT_INTRO)
      circ->base_.purpose = CIRCUIT_PURPOSE_C_INTRODUCING;
    if (kind == VANGUARD)
      circ->base_.purpose = CIRCUIT_PURPOSE_HS_VANGUARDS;
    if (kind == MEASUREMENT)
      circ->base_.purpose = CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT;
    if (kind == CANNIBALIZED)
      circ->has_opened = 1;
    if (kind == LONG_PATH)
      circuit_append_new_exit(circ, circ->cpath->extend_info);
    circ->cpath->state = CPATH_STATE_OPEN;
    circ->cpath->next->state = CPATH_STATE_OPEN;
    crypt_path_t *hop = circ->cpath->next->next;
    if (kind != EARLIER_HOP) {
      hop->state = CPATH_STATE_OPEN;
      hop = hop->next;
    }
    tor_addr_parse(&hop->extend_info->orports[0].addr, "192.0.2.1");
    hop->extend_info->orports[0].port = 9001;
    memset(hop->extend_info->identity_digest, 0x43, DIGEST_LEN);
    memset(hop->extend_info->curve25519_onion_key.public_key, 0x42,
           CURVE25519_PUBKEY_LEN);
    fourth_extend_calls = 0;
    fourth_extend_result = kind == SEND_FAILED ? -1 : 0;
    cbt_test_now = start;
    cbt_test_now.tv_sec = 1005;
    if (kind == SLOW_PREFIX)
      cbt->timeout_ms = 1000;
    tt_int_op(circuit_send_next_onion_skin(circ), OP_EQ, 0);
    tt_int_op(fourth_extend_calls, OP_EQ, 1);
    const bool reset = kind == FRESH || kind == FIXED || kind == LONG_PATH;
    tt_int_op(circ->base_.timestamp_began.tv_sec, OP_EQ,
              reset ? 1005 : 1000);
    tt_int_op(circ->build_state->expiry_time, OP_EQ, 1030);
    if (kind == SLOW_PREFIX)
      tt_int_op(circ->base_.purpose, OP_EQ, CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT);
    if (kind == LONG_PATH) {
      /* L3 vanguards use G-L2-L3-M-R. Give each extension beyond the
       * measured prefix its own budget without sampling that prefix again. */
      tt_assert(circ->cbt_prefix_measurement_done);
      tt_int_op(cbt->total_build_times, OP_EQ, 1);
      tt_int_op(cbt->circuit_build_times[0], OP_EQ, 5000);
      hop->state = CPATH_STATE_OPEN;
      hop = hop->next;
      tor_addr_parse(&hop->extend_info->orports[0].addr, "192.0.2.2");
      hop->extend_info->orports[0].port = 9001;
      memset(hop->extend_info->identity_digest, 0x44, DIGEST_LEN);
      memset(hop->extend_info->curve25519_onion_key.public_key, 0x45,
             CURVE25519_PUBKEY_LEN);
      cbt_test_now.tv_sec = 1006;
      tt_int_op(circuit_send_next_onion_skin(circ), OP_EQ, 0);
      tt_int_op(fourth_extend_calls, OP_EQ, 2);
      tt_int_op(circ->base_.timestamp_began.tv_sec, OP_EQ, 1006);
      tt_int_op(cbt->total_build_times, OP_EQ, 1);
      tt_int_op(circ->build_state->expiry_time, OP_EQ, 1030);
    }
    if (kind == FRESH) {
      /* The prefix was sampled before resetting the extension's clock. */
      tt_assert(circ->cbt_prefix_measurement_done);
      tt_int_op(cbt->total_build_times, OP_EQ, 1);
      tt_int_op(cbt->circuit_build_times[0], OP_EQ, 5000);
      cbt->timeout_ms = 1000; /* CBT can still fall after EXTEND. */
      cbt_test_now.tv_sec = 1006;
      marked_for_close = 0;
      circuit_expire_building();
      tt_int_op(marked_for_close, OP_EQ, 0);
      tt_int_op(circ->base_.purpose, OP_EQ, CIRCUIT_PURPOSE_S_CONNECT_REND);
      /* The shared timestamp intentionally shifts the hard close too. */
      circ->base_.purpose = CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT;
      cbt_test_now.tv_sec = 1061;
      circuit_expire_building();
      tt_int_op(marked_for_close, OP_EQ, 0);
      cbt_test_now.tv_sec = 1066;
      circuit_expire_building();
      tt_int_op(marked_for_close, OP_EQ, 1);
      tt_int_op(cbt->total_build_times, OP_EQ, 1);
    }
    circuit_free_(TO_CIRCUIT(circ));
    circ = NULL;
  }
 done:
  get_options_mutable()->LearnCircuitBuildTimeout = 1;
  get_options_mutable()->CircuitBuildTimeout = 0;
  circuit_free_(TO_CIRCUIT(circ));
  circuit_free_(TO_CIRCUIT(opened));
  circuit_build_times_free_timeouts(cbt);
  UNMOCK(tor_gettimeofday);
  UNMOCK(relay_send_command_from_edge_);
  UNMOCK(circuit_mark_for_close_);
}

#define TEST_CIRCUITSTATS(name, flags) \
    { #name, test_##name, (flags), &helper_pubsub_setup, NULL }

struct testcase_t circuitstats_tests[] = {
  TEST_CIRCUITSTATS(circuitstats_fresh_rend_extension, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_hoplen, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_late_firsthop, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_late_firsthop_reset, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_prefix_accounting, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_prefix_lifecycle, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_recovery, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_recovery_mixed, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_recovery_load, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_recovery_backlog, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_recovery_statefile, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_diagnostics, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_stalled_expiry, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_connection_failure, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_mixed_rendezvous, TT_FORK),
  END_OF_TESTCASES
};
