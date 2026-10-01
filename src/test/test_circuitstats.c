/* Copyright (c) 2017-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITBUILD_PRIVATE
#define CIRCUITSTATS_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CHANNEL_FILE_PRIVATE

#include "core/or/or.h"
#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"
#include "app/config/config.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitstats.h"
#include "core/or/circuituse.h"
#include "core/or/channel.h"

#include "core/or/cpath_build_state_st.h"
#include "feature/hs/hs_ident.h"
#include "core/or/crypt_path_st.h"
#include "core/or/extend_info_st.h"
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

#define TEST_CIRCUITSTATS(name, flags) \
    { #name, test_##name, (flags), &helper_pubsub_setup, NULL }

struct testcase_t circuitstats_tests[] = {
  TEST_CIRCUITSTATS(circuitstats_hoplen, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_prefix_accounting, TT_FORK),
  TEST_CIRCUITSTATS(circuitstats_prefix_lifecycle, TT_FORK),
  END_OF_TESTCASES
};

