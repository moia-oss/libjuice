/**
 * Copyright (c) 2024 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "agent.h"
#include "ice.h"
#include "juice/juice.h"
#include "socks5-proxy.h"

#include <stdatomic.h>
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define BUFFER_SIZE 4096

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static atomic_bool gathering_done1 = false;
static atomic_bool gathering_done2 = false;

static atomic_bool received1 = false;
static atomic_bool received2 = false;

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);
static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

typedef enum {
	CANDIDATE_TYPE_HOST,
	CANDIDATE_TYPE_SRFLX,
	CANDIDATE_TYPE_RELAY,
} candidate_type_t;

static int run_socks5_connectivity_test(candidate_type_t candidate_type,
                                        socks5_proxy_config_t *proxy_config) {

	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);
	bool success = true;

	received1 = false;
	received2 = false;
	gathering_done1 = false;
	gathering_done2 = false;
	agent1 = NULL;
	agent2 = NULL;
	juice_server_t *server = NULL;
	uint16_t server_port = 0;

	// Start local STUN/TURN server
	if (candidate_type == CANDIDATE_TYPE_SRFLX || candidate_type == CANDIDATE_TYPE_RELAY) {
		juice_server_credentials_t credentials = {"user", "pass", 2};
		juice_server_config_t server_config;
		memset(&server_config, 0, sizeof(server_config));
		server_config.bind_address = "127.0.0.1";
		server_config.credentials = &credentials;
		server_config.credentials_count = 1;
		server_config.max_allocations = 10;
		server_config.max_peers = 10;

		server = juice_server_create(&server_config);
		server_port = juice_server_get_port(server);
	}

	// Start the SOCKS5 proxy
	socks5_proxy_t *proxy = socks5_proxy_start(proxy_config);
	if (!proxy) {
		fprintf(stderr, "Failed to create the socks proxy\n");
		success = false;
		goto cleanup;
	}

	// SOCKS5 proxy client config
	juice_socks5_proxy_t socks5_proxy;
	memset(&socks5_proxy, 0, sizeof(socks5_proxy));
	socks5_proxy.host = "127.0.0.1";
	socks5_proxy.port = socks5_proxy_get_port(proxy);
	socks5_proxy.username = proxy_config->username;
	socks5_proxy.password = proxy_config->password;

	// Agent 1: Create agent with SOCKS5 proxy
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	juice_turn_server_t turn_server;

	switch (candidate_type) {
	case CANDIDATE_TYPE_HOST:
		break;
	case CANDIDATE_TYPE_SRFLX:
		config1.stun_server_host = "127.0.0.1";
		config1.stun_server_port = server_port;
		break;
	case CANDIDATE_TYPE_RELAY: {
		memset(&turn_server, 0, sizeof(turn_server));
		turn_server.host = "127.0.0.1";
		turn_server.port = server_port;
		turn_server.username = "user";
		turn_server.password = "pass";
		config1.turn_servers = &turn_server;
		config1.turn_servers_count = 1;
		break;
	}
	}
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
		success = false;
		goto cleanup;
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
		success = false;
		goto cleanup;
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
	int attempts = 0;
	while (!atomic_load(&gathering_done1) && attempts++ < 100) { // up to 5 seconds
		usleep(50000);                                           // 50ms
	}
	if (!atomic_load(&gathering_done1)) {
		fprintf(stderr, "Gathering 1 timed out\n");
		success = false;
		goto cleanup;
	}

	if (candidate_type == CANDIDATE_TYPE_HOST) {
		if (agent1->local.candidates_count != 1 ||
		    agent1->local.candidates[0].type != ICE_CANDIDATE_TYPE_HOST) {
			fprintf(stderr, "Expected 1 host candidate, got %d candidates (first type=%d)\n",
			        agent1->local.candidates_count,
			        agent1->local.candidates_count > 0 ? agent1->local.candidates[0].type : -1);
			success = false;
			goto cleanup;
		}
	}

	juice_gather_candidates(agent2);
	attempts = 0;
	while (!atomic_load(&gathering_done2) && attempts++ < 100) { // up to 5 seconds
		usleep(50000);                                           // 50ms
	}
	if (!atomic_load(&gathering_done2)) {
		fprintf(stderr, "Gathering 2 timed out\n");
		success = false;
		goto cleanup;
	}

	// Wait for connection to complete
	attempts = 0;
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
	success = (state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED);

	if (!success) {
		printf("ICE handshake failed: state1=%s, state2=%s\n", juice_state_to_string(state1),
		       juice_state_to_string(state2));
		goto cleanup;
	}

	printf("ICE handshake completed through SOCKS5 proxy\n");

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

	// Give a moment for data exchange
	attempts = 0;
	while ((!atomic_load(&received1) || !atomic_load(&received2)) &&
	       attempts++ < 100) { // up to 5 seconds
		usleep(50000);         // 50ms
	}
	if (!atomic_load(&received1) || !atomic_load(&received2)) {
		printf("Data exchange failed: received1=%d, received2=%d\n", received1, received2);
		success = false;
	}

cleanup:
	// Cleanup
	if (server) {
		juice_server_destroy(server);
	}
	if (agent1) {
		juice_destroy(agent1);
	}
	if (agent2) {
		juice_destroy(agent2);
	}
	if (proxy) {
		socks5_proxy_stop(proxy);
	}

	return success ? 0 : -1;
}

int test_socks5_connectivity(void) {

	socks5_proxy_config_t noauth = {NULL, NULL};
	socks5_proxy_config_t auth = {"user", "pass"};
	if (run_socks5_connectivity_test(CANDIDATE_TYPE_HOST, &noauth) ||
	    run_socks5_connectivity_test(CANDIDATE_TYPE_SRFLX, &noauth) ||
	    run_socks5_connectivity_test(CANDIDATE_TYPE_RELAY, &noauth) ||
	    run_socks5_connectivity_test(CANDIDATE_TYPE_HOST, &auth)) {
		printf("Failure\n");
		return -1;
	}
	printf("Success\n");
	return 0;
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
	atomic_store(&gathering_done1, true);
}

static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	printf("Gathering done 2\n");
	juice_set_remote_gathering_done(agent1);
	atomic_store(&gathering_done2, true);
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
	atomic_store(&received1, true);
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
	atomic_store(&received2, true);
}
