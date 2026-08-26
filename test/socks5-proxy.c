#include "socks5-proxy.h"
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TCP_BACKLOG_SIZE 10
#define MAX_DATAGRAM_SIZE 65535

#define SOCKS5_VERSION 0x05

#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

#define SOCKS5_USERPASS_VERSION 0x01
#define SOCKS5_USERPASS_SUCCESS 0x00
#define SOCKS5_USERPASS_FAILURE 0x01

struct socks5_proxy {
	pthread_t thread;
	atomic_bool running;
	int tcp_fd;
	uint16_t port;
	socks5_proxy_config_t *config;
};

static int socks5_accept_connection(socks5_proxy_t *proxy) {

	while (atomic_load(&proxy->running)) {
		struct pollfd pfd = {.fd = proxy->tcp_fd, .events = POLLIN};

		if (poll(&pfd, 1, 100) <= 0)
			continue;

		return accept(proxy->tcp_fd, NULL, NULL);
	}

	return -1;
}

static int socks5_handle_greeting(int conn_fd, socks5_proxy_config_t *proxy_config) {

	uint8_t greeting[256];
	ssize_t recv_len;
	bool supports_noauth = false;

	recv_len = recv(conn_fd, greeting, sizeof(greeting), 0);

	if (recv_len < 3 || greeting[0] != SOCKS5_VERSION) {
		return -1;
	}

	for (int i = 0; i < greeting[1]; i++) {
		if (proxy_config->username != NULL && proxy_config->password != NULL) {
			if (greeting[2 + i] == SOCKS5_AUTH_USERPASS) {
				uint8_t response[2] = {SOCKS5_VERSION, SOCKS5_AUTH_USERPASS};
				send(conn_fd, response, 2, 0);
				return 0;
			}
		} else if (greeting[2 + i] == SOCKS5_AUTH_NONE) {
			uint8_t response[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NONE};
			send(conn_fd, response, 2, 0);
			return 0;
		}
	}
	uint8_t response[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE};
	send(conn_fd, response, 2, 0);

	return -1;
}

static int socks5_handle_auth(int conn_fd, socks5_proxy_config_t *proxy_config) {
	uint8_t buffer[512];
	ssize_t buffer_len = recv(conn_fd, buffer, sizeof(buffer), 0);
	if (buffer_len < 3) {
		return -1;
	}

	uint8_t ulen = buffer[1];
	uint8_t plen = buffer[2 + ulen];

	if ((ulen == strlen(proxy_config->username)) &&
	    (memcmp(&buffer[2], proxy_config->username, ulen) == 0) &&
	    (plen == strlen(proxy_config->password)) &&
	    (memcmp(&buffer[3 + ulen], proxy_config->password, plen) == 0)) {

		uint8_t reply[] = {SOCKS5_USERPASS_VERSION, SOCKS5_USERPASS_SUCCESS};
		send(conn_fd, reply, sizeof(reply), 0);
		return 0;
	} else {
		uint8_t reply[] = {SOCKS5_USERPASS_VERSION, SOCKS5_USERPASS_FAILURE};
		send(conn_fd, reply, sizeof(reply), 0);
		return -1;
	}
}

static int socks5_handle_udp_associate(int conn_fd, struct sockaddr_in *client_udp_addr) {

	client_udp_addr->sin_family = AF_INET;

	uint8_t request[512];
	ssize_t recv_len;
	recv_len = recv(conn_fd, request, sizeof(request), 0);
	uint8_t ver = request[0];
	uint8_t cmd = request[1];
	uint8_t atyp = request[3];

	if (ver != SOCKS5_VERSION) {
		return -1;
	}

	if (cmd != SOCKS5_CMD_UDP_ASSOCIATE) {
		uint8_t reply[] = {SOCKS5_VERSION,
		                   SOCKS5_REP_COMMAND_NOT_SUPPORTED,
		                   0x00,
		                   SOCKS5_ATYP_IPV4,
		                   0,
		                   0,
		                   0,
		                   0,
		                   0,
		                   0};
		send(conn_fd, reply, sizeof(reply), 0);
		return -1;
	}

	// Parse address based on atyp

	switch (atyp) {
	case SOCKS5_ATYP_IPV4:
		memcpy(&client_udp_addr->sin_addr, &request[4], 4);
		memcpy(&client_udp_addr->sin_port, &request[8], 2);
		break;
	case SOCKS5_ATYP_IPV6:
	case SOCKS5_ATYP_DOMAIN:
		return -1;
	default: {
		uint8_t reply[] = {SOCKS5_VERSION,
		                   SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED,
		                   0x00,
		                   SOCKS5_ATYP_IPV4,
		                   0,
		                   0,
		                   0,
		                   0,
		                   0,
		                   0};
		send(conn_fd, reply, sizeof(reply), 0);
		return -1;
	}
	}

	return 0;
}

static int socks5_create_udp_relay(int conn_fd) {

	// Create UDP relay socket
	int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_fd == -1) {
		perror("udp_socket");
		return -1;
	}

	// Bind to any port
	struct sockaddr_in udp_addr;
	memset(&udp_addr, 0, sizeof(udp_addr));
	udp_addr.sin_family = AF_INET;
	udp_addr.sin_port = htons(0);
	udp_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(udp_fd, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) == -1) {
		perror("udp bind");
		close(udp_fd);
		return -1;
	}

	// Get ip address and port and store it
	socklen_t udp_addr_len = sizeof(udp_addr);
	getsockname(udp_fd, (struct sockaddr *)&udp_addr, &udp_addr_len);

	// Send UDP socket info to client
	uint8_t reply[10];
	reply[0] = SOCKS5_VERSION;
	reply[1] = SOCKS5_REP_SUCCESS;
	reply[2] = 0x00; // reserved
	reply[3] = SOCKS5_ATYP_IPV4;
	memcpy(&reply[4], &udp_addr.sin_addr, 4);
	memcpy(&reply[8], &udp_addr.sin_port, 2);
	send(conn_fd, reply, sizeof(reply), 0);

	return udp_fd;
}

static void socks5_relay_udp(socks5_proxy_t *proxy, int udp_fd,
                             struct sockaddr_in *client_udp_addr) {

	// UDP relay loop
	uint8_t buffer[MAX_DATAGRAM_SIZE];
	struct sockaddr_in sender_addr;
	socklen_t sender_len = sizeof(sender_addr);

	while (atomic_load(&proxy->running)) {
		struct pollfd pfd = {.fd = udp_fd, .events = POLLIN};
		if (poll(&pfd, 1, 100) <= 0)
			continue;

		ssize_t recv_len = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
		                            (struct sockaddr *)&sender_addr, &sender_len);

		if (recv_len < 0)
			break;
		if (recv_len < 10)
			continue;

		if (client_udp_addr->sin_port == 0) {
			*client_udp_addr = sender_addr;
		}

		struct sockaddr_in dest_addr;
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;

		if (sender_addr.sin_addr.s_addr == client_udp_addr->sin_addr.s_addr &&
		    sender_addr.sin_port == client_udp_addr->sin_port) {

			memcpy(&dest_addr.sin_addr, &buffer[4], 4);
			memcpy(&dest_addr.sin_port, &buffer[8], 2);
			sendto(udp_fd, buffer + 10, recv_len - 10, 0, (struct sockaddr *)&dest_addr,
			       sizeof(dest_addr));
		} else {
			uint8_t wrapped[MAX_DATAGRAM_SIZE];
			wrapped[0] = 0x00; // RSV
			wrapped[1] = 0x00; // RSV
			wrapped[2] = 0x00; // FRAG
			wrapped[3] = SOCKS5_ATYP_IPV4;
			memcpy(&wrapped[4], &sender_addr.sin_addr, 4);
			memcpy(&wrapped[8], &sender_addr.sin_port, 2);
			memcpy(&wrapped[10], buffer, recv_len);
			sendto(udp_fd, wrapped, recv_len + 10, 0, (struct sockaddr *)client_udp_addr,
			       sizeof(*client_udp_addr));
		}
	}
}

static void *socks5_proxy_thread(void *proxy_arg) {
	socks5_proxy_t *proxy = (socks5_proxy_t *)proxy_arg;
	int conn_fd = -1;
	int udp_fd = -1;

	if ((conn_fd = socks5_accept_connection(proxy)) == -1) {
		goto cleanup;
	}

	if (socks5_handle_greeting(conn_fd, proxy->config) == -1) {
		goto cleanup;
	}

	if (proxy->config->username != NULL && proxy->config->username != NULL) {
		if (socks5_handle_auth(conn_fd, proxy->config) == -1) {
			goto cleanup;
		}
	}

	struct sockaddr_in client_udp_addr;
	memset(&client_udp_addr, 0, sizeof(client_udp_addr));

	if (socks5_handle_udp_associate(conn_fd, &client_udp_addr) == -1) {
		goto cleanup;
	}

	if ((udp_fd = socks5_create_udp_relay(conn_fd)) == -1) {
		goto cleanup;
	}

	socks5_relay_udp(proxy, udp_fd, &client_udp_addr);

cleanup:
	close(proxy->tcp_fd);
	if (conn_fd != -1)
		close(conn_fd);
	if (udp_fd != -1)
		close(udp_fd);
	return NULL;
}

socks5_proxy_t *socks5_proxy_start(socks5_proxy_config_t *config) {

	socks5_proxy_t *proxy = malloc(sizeof(socks5_proxy_t));
	proxy->config = config;
	atomic_store(&proxy->running, true);

	// Create TCP socket
	int listen_fd;
	listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Configure socket
	struct sockaddr_in server_addr;
	socklen_t server_addr_len = sizeof(server_addr);
	memset(&server_addr, 0, server_addr_len);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(0); // let the OS choose the port
	server_addr.sin_addr.s_addr = INADDR_ANY;

	// Bind socket
	if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	// Mark socket as passive
	if (listen(listen_fd, TCP_BACKLOG_SIZE) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	getsockname(listen_fd, (struct sockaddr *)&server_addr, &server_addr_len);
	proxy->port = ntohs(server_addr.sin_port);
	proxy->tcp_fd = listen_fd;

	pthread_create(&proxy->thread, NULL, socks5_proxy_thread, (void *)proxy);

	return proxy;
}
void socks5_proxy_stop(socks5_proxy_t *proxy) {
	atomic_store(&proxy->running, false);
	pthread_join(proxy->thread, NULL);
	free(proxy);
}

uint16_t socks5_proxy_get_port(socks5_proxy_t *proxy) { return proxy->port; }
