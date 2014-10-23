/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_
#define CIRCUITMUX_PRIVATE
#define RELAY_PRIVATE
#include "or.h"
#include "channel.h"
#include "test.h"

static void
test_channel_state_is_valid(void *data)
{
  (void)data;
  tt_assert(channel_state_is_valid(CHANNEL_STATE_CLOSED));
  tt_assert(channel_state_is_valid(CHANNEL_STATE_CLOSING));
  tt_assert(channel_state_is_valid(CHANNEL_STATE_ERROR));
  tt_assert(channel_state_is_valid(CHANNEL_STATE_MAINT));
  tt_assert(channel_state_is_valid(CHANNEL_STATE_OPENING));
  tt_assert(channel_state_is_valid(CHANNEL_STATE_OPEN));
  tt_assert(!channel_state_is_valid(CHANNEL_STATE_LAST));
done:
  ;
}

static void
test_channel_listener_state_is_valid(void *data)
{
  (void)data;
  tt_assert(channel_listener_state_is_valid(CHANNEL_LISTENER_STATE_CLOSED));
  tt_assert(channel_listener_state_is_valid(CHANNEL_LISTENER_STATE_LISTENING));
  tt_assert(channel_listener_state_is_valid(CHANNEL_LISTENER_STATE_CLOSING));
  tt_assert(channel_listener_state_is_valid(CHANNEL_LISTENER_STATE_ERROR));
  tt_assert(!channel_listener_state_is_valid(CHANNEL_LISTENER_STATE_LAST));
done:
  ;
}


static void
test_channel_state_can_transition(void *data)
{
  channel_state_t transistions[][2] = {
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_CLOSED, CHANNEL_STATE_LAST},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_CLOSING, CHANNEL_STATE_LAST},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_ERROR, CHANNEL_STATE_LAST},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_MAINT, CHANNEL_STATE_LAST},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_OPENING, CHANNEL_STATE_LAST},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_OPEN, CHANNEL_STATE_LAST},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_CLOSED},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_CLOSING},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_ERROR},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_MAINT},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_OPENING},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_OPEN},
    {CHANNEL_STATE_LAST, CHANNEL_STATE_LAST},
  };
  int can_transition[] = {
    0, 0, 0, 0, 1, 0, 0,
    1, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 1, 0,
    0, 1, 1, 0, 0, 1, 0,
    0, 1, 1, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  };
  int ret = 0;
  size_t iii = 0;

  (void)data;
  for (iii = 0; iii < 49; iii++) {
    ret = channel_state_can_transition(transistions[iii][0],
                                       transistions[iii][1]);
    tt_int_op(ret, ==, can_transition[iii]);
  }
done:
  ;
}

struct testcase_t channel_tests[] = {
  { "channel_state_is_valid", test_channel_state_is_valid, 0, NULL, NULL },
  { "channel_listener_state_is_valid", test_channel_listener_state_is_valid,
      0, NULL, NULL },
  { "channel_state_can_transition", test_channel_state_can_transition,
      0, NULL, NULL },
  END_OF_TESTCASES
};
