/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_UDP_H
#define JUICE_UDP_H

#include "addr.h"
#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

struct socks5_context;

typedef struct udp_socket_config {
	const char *bind_address;
	uint16_t port_begin;
	uint16_t port_end;
	// SOCKS5 proxy (all NULL/0 to disable)
	const char *proxy_host;
	uint16_t proxy_port;
	const char *proxy_username;
	const char *proxy_password;
} udp_socket_config_t;

typedef struct udp_socket_context {
	socket_t sock;
	struct socks5_context *socks5; // NULL if no proxy, owned by context
} udp_socket_context_t;

socket_t udp_create_socket(const udp_socket_config_t *config);
int udp_open(udp_socket_context_t *ctx, const udp_socket_config_t *config);
void udp_close(udp_socket_context_t *ctx);
int udp_recvfrom(socket_t sock, char *buffer, size_t size, addr_record_t *src);
int udp_sendto(socket_t sock, const char *data, size_t size, const addr_record_t *dst);
int udp_ctx_recvfrom(udp_socket_context_t *ctx, char *buffer, size_t size, addr_record_t *src);
int udp_ctx_sendto(udp_socket_context_t *ctx, const char *data, size_t size, const addr_record_t *dst);
int udp_sendto_self(socket_t sock, const char *data, size_t size);
int udp_set_diffserv(socket_t sock, int ds);
uint16_t udp_get_port(socket_t sock);
int udp_get_bound_addr(socket_t sock, addr_record_t *record);
int udp_get_local_addr(socket_t sock, int family, addr_record_t *record); // family may be AF_UNSPEC
int udp_get_addrs(socket_t sock, addr_record_t *records, size_t count);
socket_t udp_get_control_socket(const udp_socket_context_t *ctx);
int udp_get_relay_addr(const udp_socket_context_t *ctx, addr_record_t *relay_addr);
bool udp_is_proxy_alive(const udp_socket_context_t *ctx);

#endif // JUICE_UDP_H
