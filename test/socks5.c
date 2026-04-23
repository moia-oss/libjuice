/**
 * Copyright (c) 2024 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"
#include "socks5.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

// Use exported test wrappers
#define socks5_wrap_udp _juice_socks5_wrap_udp
#define socks5_unwrap_udp _juice_socks5_unwrap_udp

int test_socks5(void) {
	// Test IPv4 wrap/unwrap
	{
		addr_record_t dst;
		struct sockaddr_in *sin = (struct sockaddr_in *)&dst.addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port = htons(12345);
		uint8_t addr_bytes[4] = {192, 168, 1, 100};
		memcpy(&sin->sin_addr, addr_bytes, 4);
		dst.len = sizeof(struct sockaddr_in);
		dst.socktype = SOCK_DGRAM;

		const char *payload = "Hello, SOCKS5!";
		size_t payload_len = strlen(payload);

		char wrapped[256];
		int wrapped_len = socks5_wrap_udp(wrapped, sizeof(wrapped), payload, payload_len, &dst);
		if (wrapped_len < 0) {
			fprintf(stderr, "socks5_wrap_udp failed for IPv4\n");
			return -1;
		}

		// Expected: 3 (header) + 7 (IPv4 addr) + payload_len
		int expected_len = 3 + 7 + (int)payload_len;
		if (wrapped_len != expected_len) {
			fprintf(stderr, "socks5_wrap_udp IPv4: expected len %d, got %d\n", expected_len,
			        wrapped_len);
			return -1;
		}

		// Unwrap
		char unwrapped[256];
		addr_record_t src;
		int data_len = socks5_unwrap_udp(wrapped, (size_t)wrapped_len, unwrapped, sizeof(unwrapped), &src);
		if (data_len < 0) {
			fprintf(stderr, "socks5_unwrap_udp failed for IPv4\n");
			return -1;
		}

		if ((size_t)data_len != payload_len) {
			fprintf(stderr, "socks5_unwrap_udp IPv4: expected data len %zu, got %d\n", payload_len,
			        data_len);
			return -1;
		}

		if (memcmp(unwrapped, payload, payload_len) != 0) {
			fprintf(stderr, "socks5_unwrap_udp IPv4: payload mismatch\n");
			return -1;
		}

		struct sockaddr_in *src_sin = (struct sockaddr_in *)&src.addr;
		if (src_sin->sin_family != AF_INET) {
			fprintf(stderr, "socks5_unwrap_udp IPv4: wrong family\n");
			return -1;
		}
		if (src_sin->sin_port != htons(12345)) {
			fprintf(stderr, "socks5_unwrap_udp IPv4: wrong port\n");
			return -1;
		}
		if (memcmp(&src_sin->sin_addr, addr_bytes, 4) != 0) {
			fprintf(stderr, "socks5_unwrap_udp IPv4: wrong address\n");
			return -1;
		}
	}

	// Test IPv6 wrap/unwrap
	{
		addr_record_t dst;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dst.addr;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(54321);
		uint8_t addr6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
		memcpy(&sin6->sin6_addr, addr6_bytes, 16);
		dst.len = sizeof(struct sockaddr_in6);
		dst.socktype = SOCK_DGRAM;

		const char *payload = "IPv6 test";
		size_t payload_len = strlen(payload);

		char wrapped[256];
		int wrapped_len = socks5_wrap_udp(wrapped, sizeof(wrapped), payload, payload_len, &dst);
		if (wrapped_len < 0) {
			fprintf(stderr, "socks5_wrap_udp failed for IPv6\n");
			return -1;
		}

		// Expected: 3 (header) + 19 (IPv6 addr) + payload_len
		int expected_len = 3 + 19 + (int)payload_len;
		if (wrapped_len != expected_len) {
			fprintf(stderr, "socks5_wrap_udp IPv6: expected len %d, got %d\n", expected_len,
			        wrapped_len);
			return -1;
		}

		// Unwrap
		char unwrapped[256];
		addr_record_t src;
		int data_len = socks5_unwrap_udp(wrapped, (size_t)wrapped_len, unwrapped, sizeof(unwrapped), &src);
		if (data_len < 0) {
			fprintf(stderr, "socks5_unwrap_udp failed for IPv6\n");
			return -1;
		}

		if ((size_t)data_len != payload_len) {
			fprintf(stderr, "socks5_unwrap_udp IPv6: expected data len %zu, got %d\n", payload_len,
			        data_len);
			return -1;
		}

		if (memcmp(unwrapped, payload, payload_len) != 0) {
			fprintf(stderr, "socks5_unwrap_udp IPv6: payload mismatch\n");
			return -1;
		}

		struct sockaddr_in6 *src_sin6 = (struct sockaddr_in6 *)&src.addr;
		if (src_sin6->sin6_family != AF_INET6) {
			fprintf(stderr, "socks5_unwrap_udp IPv6: wrong family\n");
			return -1;
		}
		if (src_sin6->sin6_port != htons(54321)) {
			fprintf(stderr, "socks5_unwrap_udp IPv6: wrong port\n");
			return -1;
		}
		if (memcmp(&src_sin6->sin6_addr, addr6_bytes, 16) != 0) {
			fprintf(stderr, "socks5_unwrap_udp IPv6: wrong address\n");
			return -1;
		}
	}

	// Test buffer too small
	{
		addr_record_t dst;
		struct sockaddr_in *sin = (struct sockaddr_in *)&dst.addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port = htons(80);
		dst.len = sizeof(struct sockaddr_in);
		dst.socktype = SOCK_DGRAM;

		const char *payload = "test";
		char tiny[5]; // too small for header + payload
		int ret = socks5_wrap_udp(tiny, sizeof(tiny), payload, strlen(payload), &dst);
		if (ret >= 0) {
			fprintf(stderr, "socks5_wrap_udp should have failed for tiny buffer\n");
			return -1;
		}
	}

	// Test unwrap with fragmentation (should reject)
	{
		char frag_data[] = {0x00, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 'X'};
		char out[256];
		addr_record_t src;
		int ret = socks5_unwrap_udp(frag_data, sizeof(frag_data), out, sizeof(out), &src);
		if (ret >= 0) {
			fprintf(stderr, "socks5_unwrap_udp should have rejected fragmented data\n");
			return -1;
		}
	}

	printf("Success\n");
	return 0;
}
