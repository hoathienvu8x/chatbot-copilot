#ifndef _WS_H
#define _WS_H

#define MAX_EVENTS 10
#define BUFFER_SIZE 2048
#define PERIODIC_MESSAGE_INTERVAL 5 // seconds

#define FIN_BIT 0x80
#define RSV1_BIT 0x40
#define RSV2_BIT 0x20
#define RSV3_BIT 0x10
#define MASK_BIT 0x80

#define WS_FR_OP_CONT 0x00
#define WS_FR_OP_TXT 0x01
#define WS_FR_OP_BIN 0x2
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA

typedef void (*websocket_callback_t)(int client_sock);
typedef void (*data_callback_t)(
  int client_sock, int opcode, const uint8_t * data, size_t length
);

struct websocket_callback {
  websocket_callback_t *onopen;
  websocket_callback_t *onclose;
  websocket_callback_t *onping;
  websocket_callback_t *onpong;
  data_callback_t *ondata;
};

int handle_websocket_handshake(int client_sock, const char *client_key);
int perform_websocket_handshake(
  int client_sock, const char *host, const char *path
);

#endif
