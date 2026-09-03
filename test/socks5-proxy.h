
#ifndef SOCKS5_PROXY_H
#define SOCKS5_PROXY_H

#include <stdint.h>

typedef struct socks5_proxy_config {
	const char *username;
	const char *password;

} socks5_proxy_config_t;

typedef struct socks5_proxy socks5_proxy_t;

socks5_proxy_t *socks5_proxy_start(socks5_proxy_config_t *config);
uint16_t socks5_proxy_get_port(socks5_proxy_t *proxy);
void socks5_proxy_stop(socks5_proxy_t *proxy);

#endif
