#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <time.h>
#include "sha1.h"
#include "b64.h"

#define MAX_EVENTS 10
#define PORT 8080
#define BUFFER_SIZE 2048
#define PERIODIC_MESSAGE_INTERVAL 5 // seconds

#define FIN_BIT 0x80
#define WS_FR_OP_CONT 0
#define WS_FR_OP_TXT  1
#define WS_FR_OP_BIN  2
#define WS_FR_OP_CLSE 8
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA

typedef struct {
  int fd;
  int is_handshaked;
  uint8_t *message_buffer;
  size_t message_length;
  uint8_t continuation_opcode;
} client_t;

typedef void (*websocket_callback_t)(int client_sock);

typedef void (*data_callback_t)(int client_sock, const uint8_t *data, size_t length);

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
client_t clients[FD_SETSIZE];
int client_count = 0;

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

void handle_websocket_handshake(int client_sock, const char *client_key) {
  char response[BUFFER_SIZE];
  const char *websocket_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char combined_key[63];
  unsigned char sha1_hash[SHA1_BLOCK_SIZE] = {0};
  char encoded_hash[25] = {0};

  snprintf(combined_key, sizeof(combined_key), "%s%s", client_key, websocket_magic_string);
  SHA1((unsigned char *)combined_key, strlen(combined_key), sha1_hash);
  base64_encode(sha1_hash, SHA1_BLOCK_SIZE, encoded_hash);

  snprintf(response, sizeof(response),
           "HTTP/1.1 101 Switching Protocols\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Accept: %s\r\n\r\n", encoded_hash);

  if (write(client_sock, response, strlen(response)) < 0) {
    perror("write");
  }
}

void append_to_message_buffer(client_t *client, const uint8_t *data, size_t length) {
  client->message_buffer = realloc(client->message_buffer, client->message_length + length);
  memcpy(client->message_buffer + client->message_length, data, length);
  client->message_length += length;
}

void parse_websocket_frame(
  int client_sock, const uint8_t *buffer, size_t length,
  data_callback_t data_callback, websocket_callback_t on_ping,
  websocket_callback_t on_pong, websocket_callback_t on_close
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
    case WS_FR_OP_CLSE: // Close frame
      printf("Received close frame from client %d\n", client->fd);
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
      close(client->fd);
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
  int epoll_fd, struct epoll_event *events, int num_events, int listen_sock,
  websocket_callback_t on_open, data_callback_t on_data,
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
        parse_websocket_frame(
          client_sock, buffer, bytes_read, on_data, on_ping, on_pong, on_close
        );
      }
    }
  }
}

// Example callback functions
void on_open(int client_sock) {
  printf("Client %d connected\n", client_sock);
}

void on_data(int client_sock, const uint8_t *data, size_t length) {
  printf("Received message from client %d: %.*s\n", client_sock, (int)length, data);
  // Echo the data back to the client
  uint8_t frame[2 + length];
  frame[0] = FIN_BIT | WS_FR_OP_TXT; // FIN + text frame
  frame[1] = length;
  memcpy(frame + 2, data, length);
  if (write(client_sock, frame, sizeof(frame)) < 0) {
    perror("write on data");
  }
}

void on_close(int client_sock) {
  printf("Client %d disconnected\n", client_sock);
}

void on_ping(int client_sock) {
  printf("Received ping from client %d\n", client_sock);
  // Send pong response
  uint8_t frame[2];
  frame[0] = FIN_BIT | WS_FR_OP_PONG; // FIN + pong frame
  frame[1] = 0x00; // No payload
  if (write(client_sock, frame, sizeof(frame)) < 0) {
    perror("write on ping");
  }
}

void on_pong(int client_sock) {
  printf("Received pong from client %d\n", client_sock);
}

void on_periodic(int client_sock) {
  const char *message = "Periodic message";
  uint8_t frame[2 + strlen(message)];
  frame[0] = FIN_BIT | WS_FR_OP_TXT; // FIN + text frame
  frame[1] = strlen(message);
  memcpy(frame + 2, message, strlen(message));
  if (write(client_sock, frame, sizeof(frame)) < 0) {
    perror("write on periodic");
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

int main() {
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

    handle_events(
      epoll_fd, events, num_events, listen_sock, on_open,
      on_data, on_close, on_ping, on_pong
    );
  }

  close(listen_sock);
  close(epoll_fd);
  return 0;
}
