/**
 * Copyright (c) 2024 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "socks5.h"
#include "log.h"

#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#endif

#define SOCKS5_HANDSHAKE_TIMEOUT_MS 10000
#define SOCKS5_BUFFER_SIZE 512

// Helper: set socket to blocking mode
static int set_blocking(socket_t sock, bool blocking) {
	ctl_t mode = blocking ? 0 : 1;
	return ioctlsocket(sock, FIONBIO, &mode);
}

// Helper: send all bytes (blocking)
static int send_all(socket_t sock, const char *data, size_t size) {
	size_t sent = 0;
	while (sent < size) {
		int ret = send(sock, data + sent, (socklen_t)(size - sent), 0);
		if (ret <= 0)
			return -1;
		sent += (size_t)ret;
	}
	return 0;
}

// Helper: receive exact number of bytes (blocking)
static int recv_all(socket_t sock, char *buf, size_t size) {
	size_t received = 0;
	while (received < size) {
		int ret = recv(sock, buf + received, (socklen_t)(size - received), 0);
		if (ret <= 0)
			return -1;
		received += (size_t)ret;
	}
	return 0;
}

// Helper: write address to buffer in SOCKS5 format (ATYP + ADDR + PORT)
// Returns number of bytes written, or -1 on failure
static int write_socks5_addr(char *buf, size_t buf_size, const addr_record_t *addr) {
	const struct sockaddr *sa = (const struct sockaddr *)&addr->addr;

	if (sa->sa_family == AF_INET) {
		if (buf_size < 7) // 1 + 4 + 2
			return -1;
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		buf[0] = SOCKS5_ATYP_IPV4;
		memcpy(buf + 1, &sin->sin_addr, 4);
		memcpy(buf + 5, &sin->sin_port, 2);
		return 7;
	} else if (sa->sa_family == AF_INET6) {
		if (buf_size < 19) // 1 + 16 + 2
			return -1;
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
		buf[0] = SOCKS5_ATYP_IPV6;
		memcpy(buf + 1, &sin6->sin6_addr, 16);
		memcpy(buf + 17, &sin6->sin6_port, 2);
		return 19;
	}

	return -1;
}

// Helper: read address from buffer in SOCKS5 format (ATYP + ADDR + PORT)
// Returns number of bytes consumed, or -1 on failure
static int read_socks5_addr(const char *buf, size_t buf_size, addr_record_t *addr) {
	if (buf_size < 1)
		return -1;

	uint8_t atyp = (uint8_t)buf[0];

	if (atyp == SOCKS5_ATYP_IPV4) {
		if (buf_size < 7) // 1 + 4 + 2
			return -1;
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr->addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, buf + 1, 4);
		memcpy(&sin->sin_port, buf + 5, 2);
		addr->len = sizeof(struct sockaddr_in);
		addr->socktype = SOCK_DGRAM;
		return 7;
	} else if (atyp == SOCKS5_ATYP_IPV6) {
		if (buf_size < 19) // 1 + 16 + 2
			return -1;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr->addr;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, buf + 1, 16);
		memcpy(&sin6->sin6_port, buf + 17, 2);
		addr->len = sizeof(struct sockaddr_in6);
		addr->socktype = SOCK_DGRAM;
		return 19;
	} else if (atyp == SOCKS5_ATYP_DOMAIN) {
		if (buf_size < 2)
			return -1;
		uint8_t domain_len = (uint8_t)buf[1];
		if (buf_size < (size_t)(2 + domain_len + 2))
			return -1;
		// We don't support domain-type relay addresses
		JLOG_WARN("SOCKS5 domain address type not supported for relay");
		return -1;
	}

	JLOG_WARN("Unknown SOCKS5 address type 0x%02X", atyp);
	return -1;
}

void socks5_init(socks5_context_t *ctx) {
	memset(ctx, 0, sizeof(*ctx));
	ctx->control_sock = INVALID_SOCKET;
	ctx->state = SOCKS5_STATE_NONE;
}

int socks5_connect(socks5_context_t *ctx, const addr_record_t *proxy_addr,
                   const char *username, const char *password) {
	ctx->proxy_addr = *proxy_addr;
	ctx->username = username;
	ctx->password = password;

	bool use_auth = (username && password && *username != '\0');

	// Create TCP socket
	int family = proxy_addr->addr.ss_family;
	ctx->control_sock = socket(family, SOCK_STREAM, 0);
	if (ctx->control_sock == INVALID_SOCKET) {
		JLOG_ERROR("Failed to create SOCKS5 control socket");
		ctx->state = SOCKS5_STATE_FAILED;
		return -1;
	}

	// Set socket timeout for the handshake
#ifdef _WIN32
	DWORD timeout = SOCKS5_HANDSHAKE_TIMEOUT_MS;
	setsockopt(ctx->control_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	setsockopt(ctx->control_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#else
	struct timeval tv;
	tv.tv_sec = SOCKS5_HANDSHAKE_TIMEOUT_MS / 1000;
	tv.tv_usec = (SOCKS5_HANDSHAKE_TIMEOUT_MS % 1000) * 1000;
	setsockopt(ctx->control_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(ctx->control_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

	// Connect to proxy (blocking)
	if (connect(ctx->control_sock, (const struct sockaddr *)&proxy_addr->addr,
	            proxy_addr->len) != 0) {
		JLOG_ERROR("Failed to connect to SOCKS5 proxy, errno=%d", sockerrno);
		goto error;
	}

	JLOG_DEBUG("Connected to SOCKS5 proxy");

	// Step 1: Send auth method negotiation
	char buf[SOCKS5_BUFFER_SIZE];
	if (use_auth) {
		buf[0] = SOCKS5_VERSION;
		buf[1] = 2; // number of methods
		buf[2] = SOCKS5_AUTH_NONE;
		buf[3] = SOCKS5_AUTH_USERPASS;
		if (send_all(ctx->control_sock, buf, 4) < 0) {
			JLOG_ERROR("Failed to send SOCKS5 auth negotiation");
			goto error;
		}
	} else {
		buf[0] = SOCKS5_VERSION;
		buf[1] = 1; // number of methods
		buf[2] = SOCKS5_AUTH_NONE;
		if (send_all(ctx->control_sock, buf, 3) < 0) {
			JLOG_ERROR("Failed to send SOCKS5 auth negotiation");
			goto error;
		}
	}

	// Step 2: Receive auth method response
	if (recv_all(ctx->control_sock, buf, 2) < 0) {
		JLOG_ERROR("Failed to receive SOCKS5 auth method response");
		goto error;
	}

	if ((uint8_t)buf[0] != SOCKS5_VERSION) {
		JLOG_ERROR("Invalid SOCKS5 version in auth response: 0x%02X", (uint8_t)buf[0]);
		goto error;
	}

	uint8_t method = (uint8_t)buf[1];
	if (method == SOCKS5_AUTH_NO_ACCEPTABLE) {
		JLOG_ERROR("SOCKS5 proxy rejected all authentication methods");
		goto error;
	}

	// Step 3: Handle authentication if needed
	if (method == SOCKS5_AUTH_USERPASS) {
		if (!use_auth) {
			JLOG_ERROR("SOCKS5 proxy requires authentication but no credentials provided");
			goto error;
		}

		// RFC 1929: username/password auth
		size_t ulen = strlen(username);
		size_t plen = strlen(password);
		if (ulen > 255 || plen > 255) {
			JLOG_ERROR("SOCKS5 username or password too long");
			goto error;
		}

		size_t pos = 0;
		buf[pos++] = SOCKS5_USERPASS_VERSION;
		buf[pos++] = (char)ulen;
		memcpy(buf + pos, username, ulen);
		pos += ulen;
		buf[pos++] = (char)plen;
		memcpy(buf + pos, password, plen);
		pos += plen;

		if (send_all(ctx->control_sock, buf, pos) < 0) {
			JLOG_ERROR("Failed to send SOCKS5 auth credentials");
			goto error;
		}

		if (recv_all(ctx->control_sock, buf, 2) < 0) {
			JLOG_ERROR("Failed to receive SOCKS5 auth response");
			goto error;
		}

		if ((uint8_t)buf[1] != 0x00) {
			JLOG_ERROR("SOCKS5 authentication failed, status=0x%02X", (uint8_t)buf[1]);
			goto error;
		}

		JLOG_DEBUG("SOCKS5 authentication successful");

	} else if (method != SOCKS5_AUTH_NONE) {
		JLOG_ERROR("Unsupported SOCKS5 auth method: 0x%02X", method);
		goto error;
	}

	// Step 4: Send UDP ASSOCIATE request
	// We specify 0.0.0.0:0 as the client address (we don't know it yet)
	buf[0] = SOCKS5_VERSION;
	buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
	buf[2] = 0x00; // reserved
	int request_len;
	if (family == AF_INET6) {
		buf[3] = SOCKS5_ATYP_IPV6;
		memset(buf + 4, 0, 16); // ::
		memset(buf + 20, 0, 2); // port 0
		request_len = 22;
	} else {
		buf[3] = SOCKS5_ATYP_IPV4;
		memset(buf + 4, 0, 4); // 0.0.0.0
		memset(buf + 8, 0, 2); // port 0
		request_len = 10;
	}
	if (send_all(ctx->control_sock, buf, request_len) < 0) {
		JLOG_ERROR("Failed to send SOCKS5 UDP ASSOCIATE request");
		goto error;
	}

	// Step 5: Receive UDP ASSOCIATE response
	// Read fixed header: VER(1) + REP(1) + RSV(1) + ATYP(1) = 4 bytes
	if (recv_all(ctx->control_sock, buf, 4) < 0) {
		JLOG_ERROR("Failed to receive SOCKS5 UDP ASSOCIATE response header");
		goto error;
	}

	if ((uint8_t)buf[0] != SOCKS5_VERSION) {
		JLOG_ERROR("Invalid SOCKS5 version in response: 0x%02X", (uint8_t)buf[0]);
		goto error;
	}

	if ((uint8_t)buf[1] != SOCKS5_REPLY_SUCCESS) {
		JLOG_ERROR("SOCKS5 UDP ASSOCIATE failed, reply=0x%02X", (uint8_t)buf[1]);
		goto error;
	}

	// Read the bound address based on ATYP
	uint8_t atyp = (uint8_t)buf[3];
	int addr_len;
	if (atyp == SOCKS5_ATYP_IPV4) {
		addr_len = 4 + 2; // addr + port
		if (recv_all(ctx->control_sock, buf + 4, addr_len) < 0) {
			JLOG_ERROR("Failed to receive SOCKS5 bound address");
			goto error;
		}
		struct sockaddr_in *sin = (struct sockaddr_in *)&ctx->relay_addr.addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, buf + 4, 4);
		memcpy(&sin->sin_port, buf + 8, 2);
		ctx->relay_addr.len = sizeof(struct sockaddr_in);
	} else if (atyp == SOCKS5_ATYP_IPV6) {
		addr_len = 16 + 2; // addr + port
		if (recv_all(ctx->control_sock, buf + 4, addr_len) < 0) {
			JLOG_ERROR("Failed to receive SOCKS5 bound address");
			goto error;
		}
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ctx->relay_addr.addr;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, buf + 4, 16);
		memcpy(&sin6->sin6_port, buf + 20, 2);
		ctx->relay_addr.len = sizeof(struct sockaddr_in6);
	} else {
		JLOG_ERROR("Unsupported SOCKS5 address type in response: 0x%02X", atyp);
		goto error;
	}
	ctx->relay_addr.socktype = SOCK_DGRAM;

	// If the relay address is 0.0.0.0 or ::, replace with the proxy address
	if (addr_is_any((const struct sockaddr *)&ctx->relay_addr.addr)) {
		JLOG_DEBUG("SOCKS5 relay address is unspecified, using proxy address");
		uint16_t port = addr_get_port((const struct sockaddr *)&ctx->relay_addr.addr);
		memcpy(&ctx->relay_addr.addr, &proxy_addr->addr, proxy_addr->len);
		ctx->relay_addr.len = proxy_addr->len;
		addr_set_port((struct sockaddr *)&ctx->relay_addr.addr, port);
	}

	// Switch control socket to non-blocking for future disconnect detection
	set_blocking(ctx->control_sock, false);

	if (JLOG_INFO_ENABLED) {
		char relay_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(&ctx->relay_addr, relay_str, ADDR_MAX_STRING_LEN);
		JLOG_INFO("SOCKS5 UDP ASSOCIATE successful, relay address: %s", relay_str);
	}

	ctx->state = SOCKS5_STATE_READY;
	return 0;

error:
	closesocket(ctx->control_sock);
	ctx->control_sock = INVALID_SOCKET;
	ctx->state = SOCKS5_STATE_FAILED;
	return -1;
}

int socks5_get_relay_addr(const socks5_context_t *ctx, addr_record_t *relay_addr) {
	if (ctx->state != SOCKS5_STATE_READY)
		return -1;

	*relay_addr = ctx->relay_addr;
	return 0;
}

socket_t socks5_get_control_socket(const socks5_context_t *ctx) {
	return ctx->control_sock;
}

int socks5_wrap_udp(char *out, size_t out_size, const char *data, size_t data_size,
                    const addr_record_t *dst) {
	// Header: RSV(2) + FRAG(1) + ATYP+ADDR+PORT(variable)
	if (out_size < 3)
		return -1;

	out[0] = 0x00; // RSV
	out[1] = 0x00; // RSV
	out[2] = 0x00; // FRAG = 0 (no fragmentation)

	int addr_written = write_socks5_addr(out + 3, out_size - 3, dst);
	if (addr_written < 0)
		return -1;

	size_t header_size = 3 + (size_t)addr_written;
	if (out_size < header_size + data_size)
		return -1;

	memcpy(out + header_size, data, data_size);
	return (int)(header_size + data_size);
}

int socks5_unwrap_udp(const char *in, size_t in_size, char *data, size_t data_size,
                      addr_record_t *src) {
	// Header: RSV(2) + FRAG(1) + ATYP+ADDR+PORT(variable)
	if (in_size < 4) // minimum: 2+1+1
		return -1;

	// Check RSV (some proxies like Dante may set non-zero values, so just log)
	if ((uint8_t)in[0] != 0 || (uint8_t)in[1] != 0) {
		JLOG_VERBOSE("Non-zero reserved field in SOCKS5 UDP header");
	}

	uint8_t frag = (uint8_t)in[2];
	if (frag != 0) {
		JLOG_WARN("SOCKS5 UDP fragmentation not supported, frag=%u", frag);
		return -1;
	}

	int addr_consumed = read_socks5_addr(in + 3, in_size - 3, src);
	if (addr_consumed < 0)
		return -1;

	size_t header_size = 3 + (size_t)addr_consumed;
	if (in_size < header_size)
		return -1;

	size_t payload_size = in_size - header_size;
	if (data_size < payload_size)
		return -1;

	memcpy(data, in + header_size, payload_size);
	return (int)payload_size;
}

bool socks5_is_alive(const socks5_context_t *ctx) {
	if (ctx->control_sock == INVALID_SOCKET)
		return false;

	// Try a non-blocking recv to check if the connection is still up
	char dummy;
	int ret = recv(ctx->control_sock, &dummy, 1, MSG_PEEK);
	if (ret == 0) {
		// Connection closed
		return false;
	}
	if (ret < 0) {
		int err = sockerrno;
		if (err == SEAGAIN || err == SEWOULDBLOCK) {
			// No data available, connection still alive
			return true;
		}
		// Other error, connection is dead
		return false;
	}
	// Got data (unexpected from proxy, but connection is alive)
	return true;
}

void socks5_destroy(socks5_context_t *ctx) {
	if (ctx->control_sock != INVALID_SOCKET) {
		closesocket(ctx->control_sock);
		ctx->control_sock = INVALID_SOCKET;
	}
	ctx->state = SOCKS5_STATE_NONE;
}

JUICE_EXPORT int _juice_socks5_wrap_udp(char *out, size_t out_size, const char *data,
                                        size_t data_size, const addr_record_t *dst) {
	return socks5_wrap_udp(out, out_size, data, data_size, dst);
}

JUICE_EXPORT int _juice_socks5_unwrap_udp(const char *in, size_t in_size, char *data,
                                          size_t data_size, addr_record_t *src) {
	return socks5_unwrap_udp(in, in_size, data, data_size, src);
}
