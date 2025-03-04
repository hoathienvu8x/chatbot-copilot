#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>

#define MAX_EVENTS 10 // Turn off when client mode
#define PORT 8080
#define BUFFER_SIZE 2048
#define PERIODIC_MESSAGE_INTERVAL 5 // seconds

#define SHA1_BLOCK_SIZE 20

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

static const char base64_table[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char base64_pad = '=';

typedef struct {
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];
} SHA1_CTX;

typedef struct {
  int fd;
  int is_handshaked;
  uint8_t *message_buffer;
  size_t message_length;
  uint8_t continuation_opcode;
} client_t;

typedef void (*websocket_callback_t)(int client_sock);
typedef void (*data_callback_t)(int client_sock, const uint8_t * data, size_t length);

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
client_t clients[FD_SETSIZE];
int client_count = 0;
// pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER; // for client mode
// client_t client;

void set_non_blocking(int sock) {
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }
  flags |= O_NONBLOCK;
  if (fcntl(sock, F_SETFL, flags) == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }
}

int create_listen_socket() {
  int listen_sock;
  struct sockaddr_in server_addr;

  listen_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sock == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
    perror("bind");
    close(listen_sock);
    exit(EXIT_FAILURE);
  }

  if (listen(listen_sock, SOMAXCONN) == -1) {
    perror("listen");
    close(listen_sock);
    exit(EXIT_FAILURE);
  }

  return listen_sock;
}

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const uint8_t* data, uint32_t len);
void SHA1Final(uint8_t digest[SHA1_BLOCK_SIZE], SHA1_CTX* context);
void SHA1(const uint8_t* data, uint32_t len, uint8_t digest[SHA1_BLOCK_SIZE]);

#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define blk0(i) (block[i] = (ROL(block[i],24)&0xFF00FF00) | (ROL(block[i],8)&0x00FF00FF))
#define blk(i) (block[i&15] = ROL(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15],1))

#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+ROL(v,5);w=ROL(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+ROL(v,5);w=ROL(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+ROL(v,5);w=ROL(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+ROL(v,5);w=ROL(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+ROL(v,5);w=ROL(w,30);

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]) {
  uint32_t a, b, c, d, e;
  uint32_t block[16];

  memcpy(block, buffer, 64);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;

  memset(block, 0, sizeof(block));
}

void SHA1Init(SHA1_CTX* context) {
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX* context, const uint8_t* data, uint32_t len) {
  uint32_t i, j;

  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3)) {
    context->count[1]++;
  }
  context->count[1] += (len >> 29);
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, (i = 64-j));
    SHA1Transform(context->state, context->buffer);
    for ( ; i + 63 < len; i += 64) {
        SHA1Transform(context->state, &data[i]);
    }
    j = 0;
  } else {
    i = 0;
  }
  memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(uint8_t digest[SHA1_BLOCK_SIZE], SHA1_CTX* context) {
  uint32_t i;
  uint8_t finalcount[8], c;

  for (i = 0; i < 8; i++) {
    finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
      >> ((3-(i & 3)) * 8) ) & 255);
  }
  c = 0200;
  SHA1Update(context, &c, 1);
  while ((context->count[0] & 504) != 448) {
    c = 0000;
    SHA1Update(context, &c, 1);
  }
  SHA1Update(context, finalcount, 8);
  for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
    digest[i] = (uint8_t)
      ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
  }
  memset(context, 0, sizeof(*context));
  memset(&finalcount, 0, sizeof(finalcount));
}

void SHA1(const uint8_t* data, uint32_t len, uint8_t digest[SHA1_BLOCK_SIZE]) {
  SHA1_CTX ctx;
  SHA1Init(&ctx);
  SHA1Update(&ctx, data, len);
  SHA1Final(digest, &ctx);
}

void base64_encode(const unsigned char *input, int length, char *output) {
  int i = 0, j = 0;
  unsigned char a3[3];
  unsigned char a4[4];

  while (length--) {
    a3[i++] = *(input++);
    if (i == 3) {
      a4[0] = (a3[0] & 0xfc) >> 2;
      a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
      a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
      a4[3] = a3[2] & 0x3f;

      for (i = 0; i < 4; i++) {
        output[j++] = base64_table[a4[i]];
      }
      i = 0;
    }
  }

  if (i) {
    for (int k = i; k < 3; k++) {
      a3[k] = '\0';
    }

    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
    a4[3] = a3[2] & 0x3f;

    for (int k = 0; k < i + 1; k++) {
      output[j++] = base64_table[a4[k]];
    }

    while (i++ < 3) {
      output[j++] = base64_pad;
    }
  }

  output[j] = '\0';
}

int is_base64(char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

char base64_decode_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int base64_decode(const char *input, unsigned char *output) {
  int i = 0, j = 0;
  int in_len = strlen(input);
  unsigned char a3[3];
  unsigned char a4[4];

  while (in_len-- && (input[j] != base64_pad) && is_base64(input[j])) {
    a4[i++] = input[j++];
    if (i == 4) {
      for (i = 0; i < 4; i++) {
        a4[i] = base64_decode_value(a4[i]);
      }

      a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
      a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
      a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

      for (i = 0; i < 3; i++) {
        output[j++] = a3[i];
      }
      i = 0;
    }
  }

  if (i) {
    for (int k = i; k < 4; k++) {
      a4[k] = 0;
    }

    for (int k = 0; k < 4; k++) {
      a4[k] = base64_decode_value(a4[k]);
    }

    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
    a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

    for (int k = 0; k < i - 1; k++) {
      output[j++] = a3[k];
    }
  }

  output[j] = '\0';

  return j;
}

void generate_random_nonce_with_length(uint8_t *nonce, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    nonce[i] = rand() % 256;
  }
}

#define generate_random_nonce(a) generate_random_nonce_with_length(a, 16)

void handle_websocket_handshake(int client_sock, const char *client_key) {
  char response[BUFFER_SIZE] = {0};
  const char *websocket_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char combined_key[BUFFER_SIZE] = {0};
  unsigned char sha1_hash[SHA1_BLOCK_SIZE] = {0};
  char encoded_hash[256] = {0};

  snprintf(combined_key, sizeof(combined_key), "%s%s", client_key, websocket_magic_string);
  SHA1((unsigned char *)combined_key, strlen(combined_key), sha1_hash);
  base64_encode((const unsigned char*)sha1_hash, SHA1_BLOCK_SIZE, encoded_hash);

  snprintf(
    response, sizeof(response),
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n\r\n",
    encoded_hash
  );

  if (write(client_sock, response, strlen(response)) < 0) {
    perror("write");
  }
}

/* For client mode
void perform_websocket_handshake(int client_sock, const char *host, const char *path) {
  char request[BUFFER_SIZE];
  const char *websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="; // example key (base64 of "the sample nonce")
  snprintf(
    request, sizeof(request),
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n",
    path, host, websocket_key
  );

  if (send(client_sock, request, strlen(request), 0) < 0) {
    perror("send");
  }
}
*/
void append_to_message_buffer(client_t *client, const uint8_t *data, size_t length) {
  client->message_buffer = realloc(client->message_buffer, client->message_length + length);
  memcpy(client->message_buffer + client->message_length, data, length);
  client->message_length += length;
}

void parse_websocket_frame(
  int client_sock, const uint8_t *buffer, size_t length,
  data_callback_t data_callback, websocket_callback_t on_ping,
  websocket_callback_t on_pong
) {
  if (length < 2) {
    fprintf(stderr, "Frame too short\n");
    return;
  }

  pthread_mutex_lock(&clients_mutex);
  client_t *client = NULL;
  for (int i = 0; i < client_count; i++) {
    if (clients[i].fd == client_sock) {
      client = &clients[i];
      break;
    }
  }
  pthread_mutex_unlock(&clients_mutex);

  if (client == NULL) {
    fprintf(stderr, "Client not found\n");
    return;
  }

  uint8_t fin = (buffer[0] & 0x80) >> 7;
  uint8_t opcode = buffer[0] & 0x0F;
  uint8_t masked = (buffer[1] & 0x80) >> 7;
  uint64_t payload_len = buffer[1] & 0x7F;

  size_t offset = 2;

  if (payload_len == 126) {
    if (length < 4) {
      fprintf(stderr, "Frame too short for 126 length\n");
      return;
    }
    payload_len = (buffer[2] << 8) | buffer[3];
    offset += 2;
  } else if (payload_len == 127) {
    if (length < 10) {
      fprintf(stderr, "Frame too short for 127 length\n");
      return;
    }
    payload_len = 0;
    for (int i = 0; i < 8; ++i) {
      payload_len = (payload_len << 8) | buffer[2 + i];
    }
    offset += 8;
  }

  uint8_t masking_key[4];
  if (masked) {
    if (length < offset + 4) {
      fprintf(stderr, "Frame too short for masking key\n");
      return;
    }
    memcpy(masking_key, buffer + offset, 4);
    offset += 4;
  }

  if (length < offset + payload_len) {
    fprintf(stderr, "Frame too short for payload data\n");
    return;
  }

  uint8_t *payload_data = malloc(payload_len);
  memcpy(payload_data, buffer + offset, payload_len);

  if (masked) {
    for (uint64_t i = 0; i < payload_len; ++i) {
      payload_data[i] ^= masking_key[i % 4];
    }
  }

  switch (opcode) {
    case WS_FR_OP_CONT: // Continuation frame
      append_to_message_buffer(client, payload_data, payload_len);
      if (fin) {
          data_callback(client_sock, client->message_buffer, client->message_length);
          free(client->message_buffer);
          client->message_buffer = NULL;
          client->message_length = 0;
      }
      break;
    case WS_FR_OP_TXT: // Text frame
    case WS_FR_OP_BIN: // Binary frame
      if (fin) {
        data_callback(client_sock, payload_data, payload_len);
      } else {
        client->continuation_opcode = opcode;
        append_to_message_buffer(client, payload_data, payload_len);
      }
      break;
    case WS_FR_OP_PING: // Ping frame
      on_ping(client_sock);
      break;
    case WS_FR_OP_PONG: // Pong frame
      on_pong(client_sock);
      break;
    default:
      fprintf(stderr, "Unknown opcode: %u\n", opcode);
      break;
  }

  free(payload_data);
}

void handle_events(
  int epoll_fd, struct epoll_event *events, int num_events,
  int listen_sock, websocket_callback_t on_open, data_callback_t on_data,
  websocket_callback_t on_close, websocket_callback_t on_ping,
  websocket_callback_t on_pong
) {
  for (int i = 0; i < num_events; i++) {
    if (events[i].data.fd == listen_sock) {
      // Accept new connection
      struct sockaddr_in client_addr;
      socklen_t client_addr_len = sizeof(client_addr);
      int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
      if (client_sock == -1) {
        perror("accept");
        continue;
      }

      set_non_blocking(client_sock);

      struct epoll_event event;
      event.events = EPOLLIN | EPOLLET;
      event.data.fd = client_sock;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sock, &event) == -1) {
        perror("epoll_ctl: client_sock");
        close(client_sock);
        continue;
      }

      pthread_mutex_lock(&clients_mutex);
      clients[client_count].fd = client_sock;
      clients[client_count].is_handshaked = 0;
      clients[client_count].message_buffer = NULL;
      clients[client_count].message_length = 0;
      client_count++;
      pthread_mutex_unlock(&clients_mutex);

      on_open(client_sock);
    } else {
      // Handle client data
      int client_sock = events[i].data.fd;
      uint8_t buffer[BUFFER_SIZE];
      int bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
      if (bytes_read == -1) {
        if (errno != EAGAIN) {
          perror("read");
          close(client_sock);
        }
        continue;
      } else if (bytes_read == 0) {
        // Connection closed by client
        pthread_mutex_lock(&clients_mutex);
        for (int j = 0; j < client_count; j++) {
          if (clients[j].fd == client_sock) {
            free(clients[j].message_buffer);
            clients[j] = clients[--client_count];
            break;
          }
        }
        pthread_mutex_unlock(&clients_mutex);
        close(client_sock);
        on_close(client_sock);
        continue;
      }

      buffer[bytes_read] = '\0';
      if (strstr((char*)buffer, "Sec-WebSocket-Key: ")) {
        // Handle WebSocket handshake
        char *client_key = strstr((char*)buffer, "Sec-WebSocket-Key: ") + 19;
        char *end_key = strstr(client_key, "\r\n");
        *end_key = '\0';
        handle_websocket_handshake(client_sock, client_key);

        pthread_mutex_lock(&clients_mutex);
        for (int j = 0; j < client_count; j++) {
          if (clients[j].fd == client_sock) {
            clients[j].is_handshaked = 1;
            break;
          }
        }
        pthread_mutex_unlock(&clients_mutex);
      } else {
        // Handle WebSocket frame
        parse_websocket_frame(client_sock, buffer, bytes_read, on_data, on_ping, on_pong);
      }
    }
  }
}

/* For client
void client_handle_events(
  int epoll_fd, struct epoll_event *events, int num_events,
  websocket_callback_t on_open, data_callback_t on_data,
  websocket_callback_t on_close, websocket_callback_t on_ping,
  websocket_callback_t on_pong
) {
  for (int i = 0; i < num_events; i++) {
    if (events[i].data.fd == client.fd) {
      uint8_t buffer[BUFFER_SIZE];
      ssize_t bytes_read = read(client.fd, buffer, sizeof(buffer));

      if (bytes_read == -1) {
        if (errno != EAGAIN) {
          perror("read");
          close(client.fd);
          on_close(client.fd);
        }
        continue;
      } else if (bytes_read == 0) {
        // Connection closed by server
        close(client.fd);
        on_close(client.fd);
        continue;
      }

      if (!client.is_handshaked) {
        // Assume handshake is successful for simplicity
        client.is_handshaked = 1;
        on_open(client.fd);
      } else {
        // Handle WebSocket frame
        parse_websocket_frame(&client, buffer, bytes_read, on_data, on_ping, on_pong);
      }
    }
  }
} */

// Example callback functions
void on_open(int client_sock) {
  printf("Client %d connected\n", client_sock);
}

void on_data(int client_sock, const uint8_t *data, size_t length) {
  printf("Received message from client %d: %.*s\n", client_sock, (int)length, data);
  // Echo the data back to the client
  uint8_t frame[2 + length];
  frame[0] = 0x81; // FIN + text frame
  frame[1] = length;
  memcpy(frame + 2, data, length);
  if (write(client_sock, frame, sizeof(frame)) < 0) {
    perror("write");
  }
}

void on_close(int client_sock) {
  printf("Client %d disconnected\n", client_sock);
}

void on_ping(int client_sock) {
  printf("Received ping from client %d\n", client_sock);
  // Send pong response
  uint8_t frame[2];
  frame[0] = 0x8A; // FIN + pong frame
  frame[1] = 0x00; // No payload
  if (write(client_sock, frame, sizeof(frame)) < 0) {
    perror("write");
  }
}

void on_pong(int client_sock) {
  printf("Received pong from client %d\n", client_sock);
}

void on_periodic(int client_sock) {
  const char *message = "Periodic message";
  uint8_t frame[2 + strlen(message)];
  frame[0] = 0x81; // FIN + text frame
  frame[1] = strlen(message);
  memcpy(frame + 2, message, strlen(message));
  if (write(client_sock, frame, sizeof(frame)) < 0) {
    perror("write");
  }
}

void *send_periodic_message(void *arg) {
  (void)arg;
  while (1) {
    sleep(PERIODIC_MESSAGE_INTERVAL);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
      if (clients[i].is_handshaked) {
        on_periodic(clients[i].fd);
      }
    }
    pthread_mutex_unlock(&clients_mutex);
  }
  return NULL;
}
/*
void *client_send_periodic_message(void *arg) {
  while (1) {
    sleep(PERIODIC_MESSAGE_INTERVAL);

    pthread_mutex_lock(&client_mutex);
    if (client.is_handshaked) {
      const char *message = "Periodic message";
      uint8_t frame[2 + strlen(message)];
      frame[0] = 0x81; // FIN + text frame
      frame[1] = strlen(message);
      memcpy(frame + 2, message, strlen(message));
      send(client.fd, frame, sizeof(frame), 0);
    }
    pthread_mutex_unlock(&client_mutex);
  }

  return NULL;
}*/

void create_websocket_frame(
  const uint8_t *message, size_t message_len, uint8_t **frames,
  size_t *frames_len, size_t chunk_size
) {
  size_t num_frames = (message_len + chunk_size - 1) / chunk_size;
  *frames_len = 0;

  // Allocate memory for all frames
  *frames = (uint8_t *)malloc(num_frames * (chunk_size + 10)); // Allocating worst case scenario for each frame

  size_t offset = 0;
  for (size_t i = 0; i < num_frames; i++) {
    uint8_t fin = (i == num_frames - 1) ? FIN_BIT : 0;
    uint8_t opcode = (i == 0) ? WS_FR_OP_TXT : WS_FR_OP_CONT;
    size_t frame_len = (i == num_frames - 1) ? (message_len - offset) : chunk_size;
    size_t header_len;

    if (frame_len <= 125) {
      header_len = 2;
    } else if (frame_len <= 65535) {
      header_len = 4;
    } else {
      header_len = 10;
    }

    (*frames)[*frames_len] = fin | opcode;

    if (frame_len <= 125) {
      (*frames)[*frames_len + 1] = frame_len;
    } else if (frame_len <= 65535) {
      (*frames)[*frames_len + 1] = 126;
      (*frames)[*frames_len + 2] = (frame_len >> 8) & 0xFF;
      (*frames)[*frames_len + 3] = frame_len & 0xFF;
    } else {
      (*frames)[*frames_len + 1] = 127;
      for (int j = 0; j < 8; ++j) {
        (*frames)[*frames_len + 9 - j] = frame_len & 0xFF;
        frame_len >>= 8;
      }
    }

    memcpy(*frames + *frames_len + header_len, message + offset, frame_len);
    *frames_len += header_len + frame_len;
    offset += frame_len;
  }
}

void free_websocket_frames(uint8_t *frames) {
  free(frames);
}

int main() {
  srand((unsigned int) time(NULL));
  uint8_t nonce[16];  // WebSocket nonces are typically 16 bytes long
  generate_random_nonce(nonce);
  char base64_nonce[25];
  base64_encode(nonce, sizeof(nonce), base64_nonce);
  printf("Generated WebSocket Nonce Key: %s\n", base64_nonce);
  return 0;
}

int main0() {
  int listen_sock = create_listen_socket();
  set_non_blocking(listen_sock);

  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    close(listen_sock);
    exit(EXIT_FAILURE);
  }

  struct epoll_event event;
  event.events = EPOLLIN | EPOLLET;
  event.data.fd = listen_sock;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock, &event) == -1) {
    perror("epoll_ctl: listen_sock");
    close(listen_sock);
    close(epoll_fd);
    exit(EXIT_FAILURE);
  }

  struct epoll_event events[MAX_EVENTS];

  pthread_t periodic_thread;
  pthread_create(&periodic_thread, NULL, send_periodic_message, NULL);

  while (1) {
    int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (num_events == -1) {
      perror("epoll_wait");
      close(listen_sock);
      close(epoll_fd);
      exit(EXIT_FAILURE);
    }

    handle_events(epoll_fd, events, num_events, listen_sock, on_open, on_data, on_close, on_ping, on_pong);
  }

  close(listen_sock);
  close(epoll_fd);
  return 0;
}
/*
int main() {
    const char *host = "echo.websocket.org";
    const char *path = "/";
    int port = 80;

    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(1);
    }

    client.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client.fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(port);

    if (connect(client.fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(client.fd);
        exit(EXIT_FAILURE);
    }

    set_non_blocking(client.fd);

    client.is_handshaked = 0;
    client.message_buffer = NULL;
    client.message_length = 0;

    perform_websocket_handshake(client.fd, host, path);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(client.fd);
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = client.fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client.fd, &event) == -1) {
        perror("epoll_ctl: client_sock");
        close(client.fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }

    struct epoll_event events[10];

    pthread_t periodic_thread;
    pthread_create(&periodic_thread, NULL, send_periodic_message, NULL);

    while (1) {
        int num_events = epoll_wait(epoll_fd, events, 10, -1);
        if (num_events == -1) {
            perror("epoll_wait");
            close(client.fd);
            close(epoll_fd);
            exit(EXIT_FAILURE);
        }

        handle_events(epoll_fd, events, num_events, on_open, on_data, on_close, on_ping, on_pong);
    }

    close(client.fd);
    close(epoll_fd);
    return 0;
}
*/
