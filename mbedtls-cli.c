#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"

#define SERVER_ADDR "example.com"
#define SERVER_PORT "443"
#define SERVER_PATH "/ws"
#define SERVER_HOST "example.com"

#define WEBSOCKET_KEY "dGhlIHNhbXBsZSBub25jZQ=="

static void websocket_handshake(mbedtls_ssl_context *ssl)
{
  char handshake[512];
  snprintf(handshake, sizeof(handshake),
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n",
    SERVER_PATH, SERVER_HOST, WEBSOCKET_KEY);

  mbedtls_ssl_write(ssl, (const unsigned char *)handshake, strlen(handshake));
}

static void websocket_send(mbedtls_ssl_context *ssl, const char *message)
{
  unsigned char frame[10];
  size_t message_len = strlen(message);
  frame[0] = 0x81;
  frame[1] = message_len;

  mbedtls_ssl_write(ssl, frame, 2);
  mbedtls_ssl_write(ssl, (const unsigned char *)message, message_len);
}

static void websocket_send_ping(mbedtls_ssl_context *ssl)
{
  unsigned char frame[2];
  frame[0] = 0x89; // Ping frame
  frame[1] = 0x00; // No payload

  mbedtls_ssl_write(ssl, frame, 2);
}

static void websocket_send_pong(mbedtls_ssl_context *ssl)
{
  unsigned char frame[2];
  frame[0] = 0x8A; // Pong frame
  frame[1] = 0x00; // No payload

  mbedtls_ssl_write(ssl, frame, 2);
}

static void websocket_handle_message(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
  unsigned char opcode = buf[0] & 0x0F;

  switch (opcode)
  {
  case 0x01: // Text frame
    printf("Received message: %.*s\n", (int)len - 2, buf + 2);
    break;
  case 0x08: // Close frame
    printf("Received close frame\n");
    mbedtls_ssl_close_notify(ssl);
    break;
  case 0x09: // Ping frame
    printf("Received ping frame\n");
    websocket_send_pong(ssl);
    break;
  case 0x0A: // Pong frame
    printf("Received pong frame\n");
    break;
  case 0x00: // Continuation frame
    printf("Received continuation frame: %.*s\n", (int)len - 2, buf + 2);
    break;
  default:
    printf("Received unknown frame\n");
    break;
  }
}

static void periodic_callback(mbedtls_ssl_context *ssl)
{
  // Example periodic callback: send a ping every 10 seconds
  websocket_send_ping(ssl);
  sleep(10);
}

int main()
{
  int ret;
  mbedtls_net_context server_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  const char *pers = "websocket_client";

  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)pers,
                                   strlen(pers))) != 0)
  {
    printf("mbedtls_ctr_drbg_seed returned %d\n", ret);
    return 1;
  }

  if ((ret = mbedtls_net_connect(&server_fd, SERVER_ADDR,
                                 SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
  {
    printf("mbedtls_net_connect returned %d\n", ret);
    return 1;
  }

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
  {
    printf("mbedtls_ssl_config_defaults returned %d\n", ret);
    return 1;
  }

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
  {
    printf("mbedtls_ssl_setup returned %d\n", ret);
    return 1;
  }

  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  if ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
  {
    printf("mbedtls_ssl_handshake returned -0x%x\n", -ret);
    return 1;
  }

  websocket_handshake(&ssl);

  unsigned char buf[512];
  int len;

  while (1)
  {
    len = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
    if (len <= 0)
      break;

    websocket_handle_message(&ssl, buf, len);

    periodic_callback(&ssl);
  }

  mbedtls_ssl_close_notify(&ssl);

  mbedtls_net_free(&server_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  return 0;
}
