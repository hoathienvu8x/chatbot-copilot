#include "ws.h"
#include "b64.h"
#include "sha1.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int generate_random_websocket_key(char *output) {
  size_t i;
  uint8_t nonce[16] = {0};
  for (i = 0; i < 16; ++i) {
    nonce[i] = rand() % 256;
  }
  return base64_encode(nonce, 16, output);
}

int generate_websocket_handshake_key(const char *key, char *output) {
  const char *websocket_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char combined_key[63] = {0};
  unsigned char sha1_hash[SHA1_BLOCK_SIZE] = {0};
  if (!key || strlen(key) != 24) return -1;
  if (snprintf(
    combined_key, sizeof(combined_key) - 1, "%s%s",
    key, websocket_magic_string
  ) <= 0) {
    return -1;
  }
  SHA1((unsigned char *)combined_key, strlen(combined_key), sha1_hash);
  return base64_encode(sha1_hash, SHA1_BLOCK_SIZE, output);
}
