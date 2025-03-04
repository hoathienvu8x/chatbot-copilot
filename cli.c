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

typedef void (*websocket_callback_t)(int client_sock);
typedef void (*data_callback_t)(int client_sock, const uint8_t *data, size_t length);

pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  int fd;
  int is_handshaked;
  uint8_t *message_buffer;
  size_t message_length;
  uint8_t continuation_opcode;
} client_t;

client_t client;

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
  client_t *client, const uint8_t *buffer, size_t length,
  data_callback_t data_callback, websocket_callback_t on_ping,
  websocket_callback_t on_pong
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
    case 0x0: // Continuation frame
      append_to_message_buffer(client, payload_data, payload_len);
      if (fin) {
        data_callback(client->fd, client->message_buffer, client->message_length);
        free(client->message_buffer);
        client->message_buffer = NULL;
        client->message_length = 0;
      }
      break;
    case 0x1: // Text frame
    case 0x2: // Binary frame
      if (fin) {
        data_callback(client->fd, payload_data, payload_len);
      } else {
        client->continuation_opcode = opcode;
        append_to_message_buffer(client, payload_data, payload_len);
      }
      break;
    case 0x9: // Ping frame
      on_ping(client->fd);
      break;
    case 0xA: // Pong frame
      on_pong(client->fd);
      break;
    default:
      fprintf(stderr, "Unknown opcode: %u\n", opcode);
      break;
  }

  free(payload_data);
}

void handle_events(
  int epoll_fd, struct epoll_event *events, int num_events,
  websocket_callback_t on_open, data_callback_t on_data,
  websocket_callback_t on_close, websocket_callback_t on_ping,
  websocket_callback_t on_pong
) {
  (void)epoll_fd;
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
}

// Example callback functions
void on_open(int client_sock) {
  (void)client_sock;
  printf("Connected to server\n");
}

void on_data(int client_sock, const uint8_t *data, size_t length) {
  (void)client_sock;
  printf("Received message: %.*s\n", (int)length, data);
}

void on_close(int client_sock) {
  (void)client_sock;
  printf("Disconnected from server\n");
}

void on_ping(int client_sock) {
  printf("Received ping\n");
  // Send pong response
  uint8_t frame[2];
  frame[0] = 0x8A; // FIN + pong frame
  frame[1] = 0x00; // No payload
  if(send(client_sock, frame, sizeof(frame), 0) <= 0) {
    perror("send");
  }
}

void on_pong(int client_sock) {
  (void)client_sock;
  printf("Received pong\n");
}

void on_periodic(int client_sock) {
  const char *message = "Periodic message from client";
  uint8_t frame[2 + strlen(message)];
  frame[0] = 0x81; // FIN + text frame
  frame[1] = strlen(message);
  memcpy(frame + 2, message, strlen(message));
  if (send(client_sock, frame, sizeof(frame), 0) <= 0) {
    perror("send");
  }
}

void *send_periodic_message(void *arg) {
  (void)arg;
  while (1) {
    sleep(PERIODIC_MESSAGE_INTERVAL);

    pthread_mutex_lock(&client_mutex);
    if (client.is_handshaked) {
      on_periodic(client.fd);
    }
    pthread_mutex_unlock(&client_mutex);
  }

  return NULL;
}

int main() {
  const char *host = "localhost";
  const char *path = "/";
  int port = 8080;

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

    handle_events(
      epoll_fd, events, num_events, on_open, on_data,
      on_close, on_ping, on_pong
    );
  }

  close(client.fd);
  close(epoll_fd);
  return 0;
}
