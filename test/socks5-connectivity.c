/**
 * Copyright (c) 2024 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
static void usleep(unsigned int usecs) { Sleep(usecs / 1000); }
#else
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// For checking if port is open
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define BUFFER_SIZE 4096
#define SOCKS5_PORT 18555

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static bool received1 = false;
static bool received2 = false;

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);
static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

#ifndef _WIN32
static pid_t proxy_pid = -1;
#endif

// Wait for a TCP port to become available
static bool wait_for_port(uint16_t port, int timeout_ms) {
	int elapsed = 0;
	while (elapsed < timeout_ms) {
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0)
			return false;

		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
#ifdef _WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		if (ret == 0)
			return true;

		usleep(100000); // 100ms
		elapsed += 100;
	}
	return false;
}

static char config_path[256] = {0};

static int write_danted_config(void) {
	snprintf(config_path, sizeof(config_path), "/tmp/libjuice-test-danted-%d.conf", (int)getpid());
	FILE *f = fopen(config_path, "w");
	if (!f) {
		perror("fopen config");
		return -1;
	}
	fprintf(f,
		"logoutput: stderr\n"
		"internal: 127.0.0.1 port = %d\n"
		"external: 127.0.0.1\n"
		"socksmethod: none\n"
		"client pass {\n"
		"  from: 127.0.0.0/8 to: 0.0.0.0/0\n"
		"}\n"
		"socks pass {\n"
		"  from: 127.0.0.0/8 to: 0.0.0.0/0\n"
		"  protocol: tcp udp\n"
		"  command: connect udpassociate udpreply\n"
		"}\n",
		SOCKS5_PORT);
	fclose(f);
	return 0;
}

static int start_socks5_proxy(void) {
#ifdef _WIN32
	fprintf(stderr, "SOCKS5 connectivity test not supported on Windows\n");
	return -1;
#else
	if (write_danted_config() < 0)
		return -1;

	proxy_pid = fork();
	if (proxy_pid < 0) {
		perror("fork");
		unlink(config_path);
		return -1;
	}

	if (proxy_pid == 0) {
		// Child: exec danted
		execlp("sockd", "sockd", "-f", config_path, NULL);
		perror("execlp sockd");
		_exit(1);
	}

	// Parent: wait for proxy to be ready
	printf("Starting SOCKS5 proxy (sockd) on port %d (pid %d)...\n", SOCKS5_PORT, proxy_pid);
	if (!wait_for_port(SOCKS5_PORT, 5000)) {
		fprintf(stderr, "SOCKS5 proxy failed to start within 5 seconds\n");
		kill(proxy_pid, SIGTERM);
		waitpid(proxy_pid, NULL, 0);
		proxy_pid = -1;
		unlink(config_path);
		return -1;
	}

	printf("SOCKS5 proxy is ready\n");
	return 0;
#endif
}

static void stop_socks5_proxy(void) {
#ifndef _WIN32
	if (proxy_pid > 0) {
		printf("Stopping SOCKS5 proxy (pid %d)...\n", proxy_pid);
		kill(proxy_pid, SIGTERM);
		waitpid(proxy_pid, NULL, 0);
		proxy_pid = -1;
	}
	if (config_path[0])
		unlink(config_path);
#endif
}

int test_socks5_connectivity(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Start the SOCKS5 proxy
	if (start_socks5_proxy() < 0) {
		printf("Skipping (sockd/dante not available)\n");
		printf("Success\n");
		return 0;
	}

	// SOCKS5 proxy config
	juice_socks5_proxy_t socks5_proxy;
	memset(&socks5_proxy, 0, sizeof(socks5_proxy));
	socks5_proxy.host = "127.0.0.1";
	socks5_proxy.port = SOCKS5_PORT;

	// Agent 1: Create agent with SOCKS5 proxy
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	config1.bind_address = "127.0.0.1";
	config1.socks5_proxy = &socks5_proxy;
	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);
	if (!agent1) {
		fprintf(stderr, "Failed to create agent 1\n");
		stop_socks5_proxy();
		return -1;
	}

	// Agent 2: Create agent without SOCKS5 proxy (direct)
	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));
	config2.bind_address = "127.0.0.1";
	config2.local_port_range_begin = 60000;
	config2.local_port_range_end = 61000;
	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;

	agent2 = juice_create(&config2);
	if (!agent2) {
		fprintf(stderr, "Failed to create agent 2\n");
		juice_destroy(agent1);
		stop_socks5_proxy();
		return -1;
	}

	// Exchange SDP descriptions
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);

	juice_set_remote_description(agent2, sdp1);

	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);

	juice_set_remote_description(agent1, sdp2);

	// Gather candidates
	juice_gather_candidates(agent1);
	sleep(2);

	juice_gather_candidates(agent2);
	sleep(2);

	// Wait for connection to complete
	int attempts = 0;
	while (attempts < 20) { // up to 10 seconds
		juice_state_t state1 = juice_get_state(agent1);
		juice_state_t state2 = juice_get_state(agent2);
		if (state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED)
			break;
		if (state1 == JUICE_STATE_FAILED || state2 == JUICE_STATE_FAILED)
			break;
		usleep(500000); // 500ms
		attempts++;
	}

	// Check states
	juice_state_t state1 = juice_get_state(agent1);
	juice_state_t state2 = juice_get_state(agent2);
	bool success = (state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED);

	if (success) {
		printf("ICE handshake completed through SOCKS5 proxy\n");
	} else {
		printf("ICE handshake failed: state1=%s, state2=%s\n", juice_state_to_string(state1),
		       juice_state_to_string(state2));
	}

	// Retrieve selected candidates
	if (success) {
		char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
		char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
		if (juice_get_selected_candidates(agent1, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
		                                  JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
			printf("Local candidate  1: %s\n", local);
			printf("Remote candidate 1: %s\n", remote);
		}
		if (juice_get_selected_candidates(agent2, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
		                                  JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
			printf("Local candidate  2: %s\n", local);
			printf("Remote candidate 2: %s\n", remote);
		}

		char localAddr[JUICE_MAX_ADDRESS_STRING_LEN];
		char remoteAddr[JUICE_MAX_ADDRESS_STRING_LEN];
		if (juice_get_selected_addresses(agent1, localAddr, JUICE_MAX_ADDRESS_STRING_LEN, remoteAddr,
		                                 JUICE_MAX_ADDRESS_STRING_LEN) == 0) {
			printf("Local address  1: %s\n", localAddr);
			printf("Remote address 1: %s\n", remoteAddr);
		}
		if (juice_get_selected_addresses(agent2, localAddr, JUICE_MAX_ADDRESS_STRING_LEN, remoteAddr,
		                                 JUICE_MAX_ADDRESS_STRING_LEN) == 0) {
			printf("Local address  2: %s\n", localAddr);
			printf("Remote address 2: %s\n", remoteAddr);
		}
	}

	// Verify data was received
	if (success) {
		// Give a moment for data exchange
		sleep(1);
		if (!received1 || !received2) {
			printf("Data exchange failed: received1=%d, received2=%d\n", received1, received2);
			success = false;
		}
	}

	// Cleanup
	juice_destroy(agent1);
	juice_destroy(agent2);
	stop_socks5_proxy();

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)user_ptr;
	printf("State 1: %s\n", juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		const char *message = "Hello from 1 via SOCKS5";
		juice_send(agent, message, strlen(message));
	}
}

static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)user_ptr;
	printf("State 2: %s\n", juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		const char *message = "Hello from 2";
		juice_send(agent, message, strlen(message));
	}
}

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	printf("Candidate 1: %s\n", sdp);
	juice_add_remote_candidate(agent2, sdp);
}

static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	printf("Candidate 2: %s\n", sdp);
	juice_add_remote_candidate(agent1, sdp);
}

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	printf("Gathering done 1\n");
	juice_set_remote_gathering_done(agent2);
}

static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	printf("Gathering done 2\n");
	juice_set_remote_gathering_done(agent1);
}

static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 1: %s\n", buffer);
	received1 = true;
}

static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 2: %s\n", buffer);
	received2 = true;
}
