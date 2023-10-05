/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.c
 * \brief XXX: Write a brief introduction to this module.
 **/

#define RELAY_MSG_PRIVATE

#include "core/or/relay_msg.h"

/*
 * Public API
 */

/** Called just before the consensus is changed with the given networkstatus_t
 * object. */
void
relay_msg_consensus_has_changed(const networkstatus_t *ns)
{
  relay_msg_enabled = get_param_enabled(ns);
}

/** Free the given relay message. */
void
relay_msg_free_(relay_msg_t *msg)
{
  if (!msg) {
    return;
  }
  tor_free(msg->body);
  tor_free(msg);
}

/** Clear a relay message as in free its content and reset all fields to 0.
 * This is useful for stack allocated memory. */
void
relay_msg_clear(relay_msg_t *msg)
{
  tor_assert(msg);
  tor_free(msg->body);
  memset(msg, 0, sizeof(*msg));
}
