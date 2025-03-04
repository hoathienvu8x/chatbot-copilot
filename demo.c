#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ws.h"

int main() {
  srand((unsigned int) time(NULL));  // Seed the random number generator with the current time
  char base64_nonce[25] = {0};
  char handshake[25] = {0};
  if (generate_random_websocket_key(base64_nonce)) {
    printf("Genrete random websocket key failed\n");
    return -1;
  }
  printf("Generated WebSocket Nonce Key: %s\n", base64_nonce);
  if (generate_websocket_handshake_key(base64_nonce, handshake)) {
    printf("Generated websocket handshake key failed\n");
    return -1;
  }
  printf("Generated WebSocket Handshake Key: %s\n", handshake);
  return 0;
}


