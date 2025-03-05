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
#define BUFFER_CHUNK (BUFFER_SIZE - 10)
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
typedef struct server_t server_t;

struct connection_t {
  int fd;
  int state;
};

struct client_t {
  int fd;
  int state;
  server_t *srv;
  uint8_t *message_buffer;
  size_t message_length;
  uint8_t continuation_opcode;
};

struct event_callback_t {
  void (*on_open)(client_t *client);
  void (*on_close)(client_t *client);
  void (*on_data)(
    client_t *client, const uint8_t opcode,
    const uint8_t *data, size_t length
  );
  void (*on_ping)(client_t *client);
  void (*on_pong)(client_t *client);
  void (*on_periodic)(server_t *server);
};

struct server_t {
  int fd;
  int epoll_fd;
  pthread_mutex_t clients_mutex;
  int client_count;
  client_t clients[FD_SETSIZE];
  struct event_callback_t events;
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

int ws_send_data(int fd, const char *data, size_t length) {
  if (!data || length == 0) return -1;
  return write(fd, data, length);
}

void ws_send_frame(
  struct connection_t *conn, int opcode, const char *data, size_t length
) {
  if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN) {
    if (!data || length == 0) return;
  }
  size_t num_frames = (length + BUFFER_CHUNK)  / BUFFER_CHUNK;
  size_t offset = 0;
  unsigned char buffer[BUFFER_SIZE] = {0};
  for (size_t i = 0; i < num_frames; i++) {
    uint8_t fin = (i == num_frames - 1) ? FIN_BIT : 0;
    uint8_t op = i == 0 ? opcode : WS_FR_OP_CONT;
    size_t frame_len = BUFFER_CHUNK;
    if (i == num_frames - 1) {
      frame_len = length - offset;
    }
    size_t header_len = 10;
    if (frame_len <= 125) {
      header_len = 2;
    } else if (frame_len <= 65535) {
      header_len = 4;
    }
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = fin | op;
    if (frame_len <= 125) {
      buffer[1] = frame_len;
    } else if (frame_len <= 65535) {
      buffer[1] = 126;
      buffer[2] = (frame_len >> 8) & 0xff;
      buffer[3] = frame_len & 0xff;
    } else {
      buffer[1] = 127;
      size_t flen = frame_len;
      for (size_t j = 2; j < 10; j++) {
        buffer[j] = flen & 0xff;
        flen >>= 8;
      }
    }
    memcpy(&buffer[header_len], data + offset, frame_len);
    offset += frame_len;
    if (ws_send_data(conn->fd, (const char *)buffer, frame_len + header_len) <= 0) {
      perror("write");
      break;
    }
  }
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

  if (ws_send_data(client_sock, response, strlen(response)) < 0) {
    perror("write");
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

  server_t *srv = client->srv;

  switch (opcode) {
    case WS_FR_OP_CONT: // Continuation frame
      append_to_message_buffer(client, payload_data, payload_len);
      if (fin) {
        if (srv && *srv->events.on_data) {
          (*srv->events.on_data)(
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
        if (srv && *srv->events.on_data) {
          (*srv->events.on_data)(
            client, opcode, payload_data, payload_len
          );
        }
      } else {
        client->continuation_opcode = opcode;
        append_to_message_buffer(client, payload_data, payload_len);
      }
      break;
    case WS_FR_OP_CLSE: // Close frame
      printf("Received close frame from client %d\n", client->fd);
      // Connection closed by client
      if (srv) {
        pthread_mutex_lock(&srv->clients_mutex);
        for (int j = 0; j < srv->client_count; j++) {
          if (srv->clients[j].fd == client->fd) {
            free(srv->clients[j].message_buffer);
            srv->clients[j] = srv->clients[--srv->client_count];
            break;
          }
        }
        pthread_mutex_unlock(&srv->clients_mutex);
        if (*srv->events.on_close) {
          (*srv->events.on_close)(client);
        }
      }
      close(client->fd);
      break;
    case WS_FR_OP_PING: // Ping frame
      if (srv && *srv->events.on_ping) {
        (*srv->events.on_ping)(client);
      } else {
        ws_send_frame((struct connection_t *)client, WS_FR_OP_PONG, NULL, 0);
      }
      break;
    case WS_FR_OP_PONG: // Pong frame
      if (srv && *srv->events.on_pong) {
        (*srv->events.on_pong)(client);
      }
      break;
    default:
      fprintf(stderr, "Unknown opcode: %u\n", opcode);
      break;
  }

  free(payload_data);
}

void handle_events(
  server_t *srv , struct epoll_event *events, int num_events
) {
  for (int i = 0; i < num_events; i++) {
    if (events[i].data.fd == srv->fd) {
      // Accept new connection
      struct sockaddr_in client_addr;
      socklen_t client_addr_len = sizeof(client_addr);
      int client_sock = accept(srv->fd, (struct sockaddr*)&client_addr, &client_addr_len);
      if (client_sock == -1) {
        perror("accept");
        continue;
      }

      set_non_blocking(client_sock);

      struct epoll_event event;
      event.events = EPOLLIN | EPOLLET;
      event.data.fd = client_sock;
      if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, client_sock, &event) == -1) {
        perror("epoll_ctl: client_sock");
        close(client_sock);
        continue;
      }

      pthread_mutex_lock(&srv->clients_mutex);
      srv->clients[srv->client_count].fd = client_sock;
      srv->clients[srv->client_count].state = WS_STATE_CONNECTING;
      srv->clients[srv->client_count].message_buffer = NULL;
      srv->clients[srv->client_count].message_length = 0;
      srv->clients[srv->client_count].srv = srv;
      client_t *cli = &srv->clients[srv->client_count];
      srv->client_count++;
      pthread_mutex_unlock(&srv->clients_mutex);
      if (*srv->events.on_open) {
        (*srv->events.on_open)(cli);
      }
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
        pthread_mutex_lock(&srv->clients_mutex);
        for (int j = 0; j < srv->client_count; j++) {
          if (srv->clients[j].fd == client_sock) {
            free(srv->clients[j].message_buffer);
            srv->clients[j] = srv->clients[--srv->client_count];
            break;
          }
        }
        pthread_mutex_unlock(&srv->clients_mutex);
        close(client_sock);
        /* if(srv->events.on_close) {
          (srv->events.on_close)(client);
        } */
        continue;
      }

      buffer[bytes_read] = '\0';
      if (strstr((char*)buffer, "Sec-WebSocket-Key: ")) {
        // Handle WebSocket handshake
        char *client_key = strstr((char*)buffer, "Sec-WebSocket-Key: ") + 19;
        char *end_key = strstr(client_key, "\r\n");
        *end_key = '\0';
        handle_websocket_handshake(client_sock, client_key);

        pthread_mutex_lock(&srv->clients_mutex);
        for (int j = 0; j < srv->client_count; j++) {
          if (srv->clients[j].fd == client_sock) {
            srv->clients[j].state = WS_STATE_OPEN;
            break;
          }
        }
        pthread_mutex_unlock(&srv->clients_mutex);
      } else {
        client_t *cli = NULL;
        pthread_mutex_lock(&srv->clients_mutex);
        for (int j = 0; j < srv->client_count; j++) {
          if (srv->clients[j].fd == client_sock) {
            cli = &srv->clients[j];
            break;
          }
        }
        pthread_mutex_unlock(&srv->clients_mutex);
        // Handle WebSocket frame
        if (!cli) continue;
        parse_websocket_frame(cli, buffer, bytes_read);
      }
    }
  }
}

// Example callback functions
void on_open(client_t *client) {
  if (!client) return;
  printf("Client %d connected\n", client->fd);
}

void on_data(
  client_t *client, const uint8_t opcode, const uint8_t *data, size_t length
) {
  if (opcode == WS_FR_OP_TXT) {
    printf("Received message from client %d: %.*s\n", client->fd, (int)length, data);
  } else {
    printf("Received message from client %d: %d bytes\n", client->fd, (int)length);
  }
  if (!client || client->state != WS_STATE_OPEN) return;
  // Echo the data back to the client
  ws_send_frame((struct connection_t *)client, opcode, (const char *)data, length);
}

void on_close(client_t *client) {
  if (!client) return;
  printf("Client %d disconnected\n", client->fd);
}

void on_ping(client_t *client) {
  if (!client) return;
  printf("Received ping from client %d\n", client->fd);
  if (client->state != WS_STATE_OPEN) return;
  // Send pong response
  ws_send_frame((struct connection_t *)client, WS_FR_OP_PONG, NULL, 0);
}

void on_pong(client_t *client) {
  if (!client) return;
  printf("Received pong from client %d\n", client->fd);
}

void on_periodic(server_t *srv) {
  if (!srv) return;

  pthread_mutex_lock(&srv->clients_mutex);
  for (int i = 0; i < srv->client_count; i++) {
    if (srv->clients[i].state == WS_STATE_OPEN) {
      const char *message = "Periodic message";
      ws_send_frame(
        (struct connection_t *)&srv->clients[i], WS_FR_OP_TXT, message, strlen(message)
      );
    }
  }
  pthread_mutex_unlock(&srv->clients_mutex);
}

void *send_periodic_message(void *arg) {
  server_t *srv = (server_t *)arg;
  if (!srv || !(*srv->events.on_periodic)) return NULL;
  while (1) {
    sleep(PERIODIC_MESSAGE_INTERVAL);

    if (srv->is_stop) break;

    (*srv->events.on_periodic)(srv);
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

  server_t srv;
  memset(&srv, 0, sizeof(srv));

  srv.fd = listen_sock;
  srv.epoll_fd = epoll_fd;

  srv.events.on_open = on_open;
  srv.events.on_close = on_close;
  srv.events.on_ping = on_ping;
  srv.events.on_pong = on_pong;
  srv.events.on_data = on_data;
  srv.events.on_periodic = on_periodic;

  if (pthread_mutex_init(&srv.clients_mutex, NULL) != 0) {
    goto done;
  }

  struct epoll_event events[MAX_EVENTS];

  pthread_t periodic_thread;
  pthread_create(&periodic_thread, NULL, send_periodic_message, &srv);

  while (1) {
    int num_events = epoll_wait(srv.epoll_fd, events, MAX_EVENTS, -1);
    if (num_events == -1) {
      perror("epoll_wait");
      srv.is_stop = 1;
      break;
    }

    handle_events(&srv, events, num_events);
  }
  pthread_mutex_destroy(&srv.clients_mutex);
  pthread_join(periodic_thread, NULL);

done:
  close(srv.fd);
  close(srv.epoll_fd);
  return 0;
}
