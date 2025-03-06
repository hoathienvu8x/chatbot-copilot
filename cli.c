#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <time.h>

#define BUFFER_SIZE 2048
#define PERIODIC_MESSAGE_INTERVAL 5 // seconds

#define FIN_BIT 0x80
#define WS_FR_OP_CONT 0
#define WS_FR_OP_TXT  1
#define WS_FR_OP_BIN  2
#define WS_FR_OP_CLSE 8
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA

#define WS_STATE_CONNECTING 0
#define WS_STATE_OPEN       1
#define WS_STATE_CLOSING    2
#define WS_STATE_CLOSED     3

typedef struct client_t client_t;

struct client_t {
  int fd;
  int is_handshaked;
  int epoll_fd;
  pthread_mutex_t client_mutex;
  uint8_t *message_buffer;
  size_t message_length;
  uint8_t continuation_opcode;
  void (*on_open)(client_t *client);
  void (*on_close)(client_t *client);
  void (*on_ping)(client_t *client);
  void (*on_pong)(client_t *client);
  void (*on_data)(
    client_t *client, const uint8_t opcode,
    const uint8_t *data, size_t length
  );
  void (*on_periodic)(client_t *client);
  int is_stop;
};

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

  if (send(client_sock, request, strlen(request), 0) <= 0) {
    perror("send");
  }
}

void append_to_message_buffer(client_t *client, const uint8_t *data, size_t length) {
  client->message_buffer = realloc(client->message_buffer, client->message_length + length);
  memcpy(client->message_buffer + client->message_length, data, length);
  client->message_length += length;
}

void parse_websocket_frame(
  client_t *client, const uint8_t *buffer, size_t length
) {
  if (length < 2) {
    fprintf(stderr, "Frame too short\n");
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
        if (*client->on_data) {
          (*client->on_data)(
            client, client->continuation_opcode,
            client->message_buffer, client->message_length
          );
        }
        free(client->message_buffer);
        client->message_buffer = NULL;
        client->message_length = 0;
      }
      break;
    case WS_FR_OP_TXT: // Text frame
    case WS_FR_OP_BIN: // Binary frame
      if (fin) {
        if (*client->on_data) {
          (*client->on_data)(client, opcode, payload_data, payload_len);
        }
      } else {
        client->continuation_opcode = opcode;
        append_to_message_buffer(client, payload_data, payload_len);
      }
      break;
    case 0x9: // Ping frame
      if (*client->on_ping) {
        (*client->on_ping)(client);
      } else {
        // Send pong response
        uint8_t frame[2];
        frame[0] = 0x8A; // FIN + pong frame
        frame[1] = 0x00; // No payload
        if(send(client->fd, frame, sizeof(frame), 0) <= 0) {
          perror("send");
        }
      }
      break;
    case 0xA: // Pong frame
      if (*client->on_pong) {
        (*client->on_pong)(client);
      }
      break;
    default:
      fprintf(stderr, "Unknown opcode: %u\n", opcode);
      break;
  }

  free(payload_data);
}

void handle_events(
  client_t *client, struct epoll_event *events, int num_events
) {
  for (int i = 0; i < num_events; i++) {
    if (events[i].data.fd == client->fd) {
      uint8_t buffer[BUFFER_SIZE];
      ssize_t bytes_read = read(client->fd, buffer, sizeof(buffer));

      if (bytes_read == -1) {
        if (errno != EAGAIN) {
          perror("read");
          if (*client->on_close) {
            (*client->on_close)(client);
          }
          close(client->fd);
        }
        continue;
      } else if (bytes_read == 0) {
        // Connection closed by server
        close(client->fd);
        if (*client->on_close) {
          (*client->on_close)(client);
        }
        continue;
      }

      if (!client->is_handshaked) {
        // Assume handshake is successful for simplicity
        client->is_handshaked = 1;
        if (*client->on_open) {
          (*client->on_open)(client);
        }
      } else {
        // Handle WebSocket frame
        parse_websocket_frame(client, buffer, bytes_read);
      }
    }
  }
}

// Example callback functions
void on_open(client_t *client) {
  if (!client) return;
  printf("Connected to server\n");
}

void on_data(client_t *client, const uint8_t opcode, const uint8_t *data, size_t length) {
  if (!client) return;
  if (opcode == WS_FR_OP_TXT) {
    printf("Received message: %.*s\n", (int)length, data);
  } else {
    printf("Received message: %d bytess\n", (int)length);
  }
}

void on_close(client_t *client) {
  if (!client) return;
  printf("Disconnected from server\n");
}

void on_ping(client_t *client) {
  printf("Received ping\n");
  if (!client) return;
  // Send pong response
  uint8_t frame[2];
  frame[0] = 0x8A; // FIN + pong frame
  frame[1] = 0x00; // No payload
  if(send(client->fd, frame, sizeof(frame), 0) <= 0) {
    perror("send");
  }
}

void on_pong(client_t *client) {
  (void)client;
  printf("Received pong\n");
}

void on_periodic(client_t *client) {
  if (!client) return;
  const char *message = "Periodic message from client";
  uint8_t frame[2 + strlen(message)];
  frame[0] = 0x81; // FIN + text frame
  frame[1] = strlen(message);
  memcpy(frame + 2, message, strlen(message));
  if (send(client->fd, frame, sizeof(frame), 0) <= 0) {
    perror("send");
  }
}

void *send_periodic_message(void *arg) {
  client_t *client = (client_t *)arg;
  if (!client || !(*client->on_periodic)) return NULL;
  while (1) {
    sleep(PERIODIC_MESSAGE_INTERVAL);

    pthread_mutex_lock(&client->client_mutex);

    if (client->is_stop) break;

    if (client->is_handshaked) {
      (*client->on_periodic)(client);
    }
    pthread_mutex_unlock(&client->client_mutex);
  }

  return NULL;
}

int main() {
  const char *host = "localhost";
  const char *path = "/";
  int port = 8080;
  client_t client;

  struct hostent *server = gethostbyname(host);
  if (server == NULL) {
    fprintf(stderr, "ERROR, no such host\n");
    exit(1);
  }

  memset(&client, 0, sizeof(client_t));

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

  client.on_open = on_open;
  client.on_close = on_close;
  client.on_data = on_data;
  client.on_periodic = on_periodic;

  perform_websocket_handshake(client.fd, host, path);

  client.epoll_fd = epoll_create1(0);
  if (client.epoll_fd == -1) {
    perror("epoll_create1");
    close(client.fd);
    exit(EXIT_FAILURE);
  }

  struct epoll_event event;
  event.events = EPOLLIN | EPOLLET;
  event.data.fd = client.fd;
  if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, client.fd, &event) == -1) {
    perror("epoll_ctl: client_sock");
    goto done;
  }

  struct epoll_event events[10];

  if (pthread_mutex_init(&client.client_mutex, NULL) != 0) {
    goto done;
  }

  pthread_t periodic_thread;
  pthread_create(&periodic_thread, NULL, send_periodic_message, &client);

  while (1) {
    int num_events = epoll_wait(client.epoll_fd, events, 10, -1);
    if (num_events == -1) {
      perror("epoll_wait");
      client.is_stop = 1;
      break;
    }

    handle_events(&client, events, num_events);
  }
  uint8_t frame[2];
  frame[0] = WS_FR_OP_CLSE | FIN_BIT; // FIN + pong frame
  frame[1] = 0x00; // No payload
  if(send(client.fd, frame, sizeof(frame), 0) <= 0) {
    perror("send");
  }
  pthread_mutex_destroy(&client.client_mutex);
  pthread_join(periodic_thread, NULL);

done:
  close(client.fd);
  close(client.epoll_fd);
  return 0;
}
