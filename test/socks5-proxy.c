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
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

struct socks5_proxy {
	pthread_t thread;
	atomic_bool running;
	int tcp_fd;
	uint16_t port;
};

static void *socks5_proxy_thread(void *arg) {
	socks5_proxy_t *proxy = (socks5_proxy_t *)arg;
	int client_sockfd = -1;
	int udp_sockfd = -1;

	// Accept client connection
	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	socklen_t addr_len = sizeof(client_addr);

	while (atomic_load(&proxy->running)) {
		struct pollfd pfd = {.fd = proxy->tcp_fd, .events = POLLIN};

		if (poll(&pfd, 1, 100) <= 0)
			continue;

		if ((client_sockfd = accept(proxy->tcp_fd, (struct sockaddr *)&client_addr, &addr_len)) ==
		    -1) {
			goto cleanup;
		}
		break;
	}
	if (!atomic_load(&proxy->running))
		goto cleanup;

	// Conduct greeting phase and detect auth method from greeting message (currently only no auth
	// supported)
	uint8_t greeting[256];
	ssize_t n;
	bool supports_noauth = false;

	n = recv(client_sockfd, greeting, sizeof(greeting), 0);

	if (n < 3 || greeting[0] != SOCKS5_VERSION)
		goto cleanup;

	for (int i = 0; i < greeting[1]; i++) {
		if (greeting[2 + i] == SOCKS5_AUTH_NONE) {
			supports_noauth = true;
			break;
		}
	}
	uint8_t response[2] = {SOCKS5_VERSION, supports_noauth ? SOCKS5_AUTH_NONE : 0xFF};
	send(client_sockfd, response, 2, 0);

	// Conduct request phase
	uint8_t request[512];
	n = recv(client_sockfd, request, sizeof(request), 0);
	uint8_t ver = request[0];
	uint8_t cmd = request[1];
	uint8_t atyp = request[3];

	if (ver != SOCKS5_VERSION)
		goto cleanup;

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
		send(client_sockfd, reply, sizeof(reply), 0);
		goto cleanup;
	}

	// Parse address based on atyp
	struct sockaddr_in client_udp_addr;
	memset(&client_udp_addr, 0, sizeof(client_udp_addr));
	client_udp_addr.sin_family = AF_INET;

	switch (atyp) {
	case SOCKS5_ATYP_IPV4:
		memcpy(&client_udp_addr.sin_addr, &request[4], 4);
		memcpy(&client_udp_addr.sin_port, &request[8], 2);
		break;
	case SOCKS5_ATYP_IPV6:
	case SOCKS5_ATYP_DOMAIN:
		goto cleanup;
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
		send(client_sockfd, reply, sizeof(reply), 0);
		goto cleanup;
	}
	}

	// Create UDP socket
	udp_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_sockfd == -1) {
		perror("udp_socket");
		goto cleanup;
	}

	// Bind to any port
	struct sockaddr_in udp_addr;
	memset(&udp_addr, 0, sizeof(udp_addr));
	udp_addr.sin_family = AF_INET;
	udp_addr.sin_port = htons(0);
	udp_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(udp_sockfd, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) == -1) {
		perror("udp bind");
		goto cleanup;
	}

	// Get ip address and port and store it
	socklen_t udp_addr_len = sizeof(udp_addr);
	getsockname(udp_sockfd, (struct sockaddr *)&udp_addr, &udp_addr_len);

	// Send UDP socket info to client
	uint8_t reply[10];
	reply[0] = SOCKS5_VERSION;
	reply[1] = SOCKS5_REP_SUCCESS;
	reply[2] = 0x00; // reserved
	reply[3] = SOCKS5_ATYP_IPV4;
	memcpy(&reply[4], &udp_addr.sin_addr, 4);
	memcpy(&reply[8], &udp_addr.sin_port, 2);
	send(client_sockfd, reply, sizeof(reply), 0);

	// UDP relay loop
	uint8_t buffer[MAX_DATAGRAM_SIZE];
	struct sockaddr_in sender_addr;
	socklen_t sender_len = sizeof(sender_addr);

	while (atomic_load(&proxy->running)) {
		struct pollfd pfd = {.fd = udp_sockfd, .events = POLLIN};
		if (poll(&pfd, 1, 100) <= 0)
			continue;

		ssize_t recv_len = recvfrom(udp_sockfd, buffer, sizeof(buffer), 0,
		                            (struct sockaddr *)&sender_addr, &sender_len);

		if (recv_len < 0)
			break;
		if (recv_len < 10)
			continue;

		if (client_udp_addr.sin_port == 0) {
			client_udp_addr = sender_addr;
		}

		struct sockaddr_in dest_addr;
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;

		if (sender_addr.sin_addr.s_addr == client_udp_addr.sin_addr.s_addr &&
		    sender_addr.sin_port == client_udp_addr.sin_port) {

			memcpy(&dest_addr.sin_addr, &buffer[4], 4);
			memcpy(&dest_addr.sin_port, &buffer[8], 2);
			sendto(udp_sockfd, buffer + 10, recv_len - 10, 0, (struct sockaddr *)&dest_addr,
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
			sendto(udp_sockfd, wrapped, recv_len + 10, 0, (struct sockaddr *)&client_udp_addr,
			       sizeof(client_udp_addr));
		}
	}

cleanup:
	close(proxy->tcp_fd);
	if (client_sockfd != -1)
		close(client_sockfd);
	if (udp_sockfd != -1)
		close(udp_sockfd);
	return NULL;
}

socks5_proxy_t *socks5_proxy_start(socks5_proxy_config_t *config) {

	socks5_proxy_t *proxy = malloc(sizeof(socks5_proxy_t));
	atomic_store(&proxy->running, true);

	// Create TCP socket
	int sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1) {
		// TODO: write better error message
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
	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	// Mark socket as passive
	if (listen(sockfd, TCP_BACKLOG_SIZE) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	getsockname(sockfd, (struct sockaddr *)&server_addr, &server_addr_len);
	proxy->port = ntohs(server_addr.sin_port);
	proxy->tcp_fd = sockfd;

	pthread_create(&proxy->thread, NULL, socks5_proxy_thread, (void *)proxy);

	return proxy;
}
void socks5_proxy_stop(socks5_proxy_t *proxy) {
	atomic_store(&proxy->running, false);
	pthread_join(proxy->thread, NULL);
	free(proxy);
}

uint16_t socks5_proxy_get_port(socks5_proxy_t *proxy) { return proxy->port; }
