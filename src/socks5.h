/**
 * Copyright (c) 2024 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_SOCKS5_H
#define JUICE_SOCKS5_H

#include "addr.h"
#include "juice.h"
#include "socket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// SOCKS5 protocol constants (RFC 1928)
#define SOCKS5_VERSION 0x05

// Authentication methods
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

// Commands
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

// Address types
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

// Reply codes
#define SOCKS5_REPLY_SUCCESS 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_NOT_ALLOWED 0x02
#define SOCKS5_REPLY_NET_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONN_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ATYP_NOT_SUPPORTED 0x08

// Username/password auth (RFC 1929)
#define SOCKS5_USERPASS_VERSION 0x01

// Max overhead: 2 (RSV) + 1 (FRAG) + 1 (ATYP) + 16 (IPv6) + 2 (PORT) = 22
#define SOCKS5_UDP_HEADER_MAX_SIZE 22
// IPv4 overhead: 2 + 1 + 1 + 4 + 2 = 10
#define SOCKS5_UDP_HEADER_IPV4_SIZE 10
// IPv6 overhead: 2 + 1 + 1 + 16 + 2 = 22
#define SOCKS5_UDP_HEADER_IPV6_SIZE 22

typedef enum socks5_state {
	SOCKS5_STATE_NONE = 0,
	SOCKS5_STATE_READY,
	SOCKS5_STATE_FAILED
} socks5_state_t;

typedef struct socks5_context {
	socket_t control_sock;
	socks5_state_t state;
	addr_record_t relay_addr;       // UDP relay address returned by proxy
	addr_record_t proxy_addr;       // Resolved proxy address
	const char *username;           // Borrowed pointer (owned by agent config)
	const char *password;           // Borrowed pointer (owned by agent config)
} socks5_context_t;

// Initialize context (does not connect yet)
void socks5_init(socks5_context_t *ctx);

// Perform the full SOCKS5 handshake synchronously (blocking).
// Creates a TCP connection to the proxy, authenticates, and sends UDP ASSOCIATE.
// On success, ctx->relay_addr is set and ctx->state is SOCKS5_STATE_READY.
// Returns 0 on success, -1 on failure.
int socks5_connect(socks5_context_t *ctx, const addr_record_t *proxy_addr,
                   const char *username, const char *password);

// Get the UDP relay address (only valid when state == SOCKS5_STATE_READY)
int socks5_get_relay_addr(const socks5_context_t *ctx, addr_record_t *relay_addr);

// Get the control socket fd (for polling disconnect detection)
socket_t socks5_get_control_socket(const socks5_context_t *ctx);

// Wrap outgoing UDP data with SOCKS5 UDP header.
// Writes to out buffer. Returns total length on success, -1 on failure.
int socks5_wrap_udp(char *out, size_t out_size, const char *data, size_t data_size,
                    const addr_record_t *dst);

// Unwrap incoming UDP data by stripping SOCKS5 UDP header.
// Writes to data buffer and extracts source address to src.
// Returns data length on success, -1 on failure.
int socks5_unwrap_udp(const char *in, size_t in_size, char *data, size_t data_size,
                      addr_record_t *src);

// Check if the control connection is still alive.
// Returns true if alive, false if disconnected.
bool socks5_is_alive(const socks5_context_t *ctx);

// Destroy context, close control socket
void socks5_destroy(socks5_context_t *ctx);

// Export for tests
JUICE_EXPORT int _juice_socks5_wrap_udp(char *out, size_t out_size, const char *data,
                                        size_t data_size, const addr_record_t *dst);
JUICE_EXPORT int _juice_socks5_unwrap_udp(const char *in, size_t in_size, char *data,
                                          size_t data_size, addr_record_t *src);

#endif // JUICE_SOCKS5_H
