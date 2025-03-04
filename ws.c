#include "ws.h"
#include "b64.h"
#include <stdlib.h>

int generate_random_websocket_key(char *output) {
  size_t i;
  uint8_t nonce[16] = {0};
  for (i = 0; i < 16; ++i) {
    nonce[i] = rand() % 256;
  }
  return base64_encode(nonce, 16, output);
}
