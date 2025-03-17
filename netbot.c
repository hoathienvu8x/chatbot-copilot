#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include "netbot.h"
#include "chatbot.h"
#include "cJSON.h"

#define CHATBOT_PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

static int set_non_blocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int send_message(int fd, const char* message) {
  int retval = send(fd, message, strlen(message), 0);
  if (retval < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
  }
  return retval;
}

static int read_message(int fd, void *buf, size_t len) {
  int retval = read(fd, buf, len);
  if (retval < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return -EAGAIN;
    return -1;
  }
  return retval;
}

static int sendJSONResponse(int client_socket, const char *message) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "response", message);
    #ifndef NDEBUG
    const char *json_response = cJSON_Print(response);
    #else
    const char *json_response = cJSON_PrintUnformatted(response);
    #endif
    int ret = send_message(client_socket, json_response);
    cJSON_Delete(response);
    free((void *)json_response);
    if (ret <= 0) return -1;
    return 0;
}

static int handleClientMessage(int client_socket) {
  char buffer[BUFFER_SIZE];
  int bytes_read = read_message(client_socket, buffer, sizeof(buffer) - 1);
  if (bytes_read <= 0) {
    if (bytes_read == -EAGAIN) return 0;
    #ifndef NDEBUG
    printf("Client disconnected\n");
    #endif
    return -1;
  }
  buffer[bytes_read] = '\0';
  #ifndef NDEBUG
  printf("Received message: %s\n", buffer);
  #endif
  const char *resp = handleInput(buffer);
  if (sendJSONResponse(client_socket, resp) < 0) {
    return -1;
  }
  if (
    chatbot_strcasestr(buffer, "bye") != NULL ||
    chatbot_strcasestr(buffer, "exit") != NULL
  ) {
    return -1;
  }
  return 0;
}

static int handleServerResponse(int server_socket) {
  char buffer[BUFFER_SIZE];
  int bytes_read = read_message(server_socket, buffer, sizeof(buffer) - 1);
  if (bytes_read <= 0) {
    if (bytes_read == -EAGAIN) return 0;
    #ifndef NDEBUG
    printf("Server disconnected\n");
    #endif
    return -1;
  }
  buffer[bytes_read] = '\0';
  cJSON *obj = cJSON_Parse(buffer);
  if (!cJSON_IsObject(obj) || !cJSON_HasObjectItem(obj, "response")) {
    printf("Server: %s\n", buffer);
  } else {
    cJSON *response = cJSON_GetObjectItem(obj, "response");
    if (!cJSON_IsString(response)) {
      printf("Server: %s\n", buffer);
    } else {
      printf("Server: %s\n", cJSON_GetStringValue(response));
    }
  }
  cJSON_free(obj);
  return 0;
}

static int chatbot_create_socket(
  const char *host, const char *port,
  int (*check)(int , const struct sockaddr *, socklen_t)
) {
  struct addrinfo hints, *results, *rp;
  int sock = -1, reuse = 1, rc;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &results)) {
    #ifndef NDEBUG
    fprintf(stderr, "getaddrinfo failed\n");
    #endif
    return -1;
  }

  for (rp = results; rp != NULL; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0) continue;
    rc = setsockopt(
      sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
      (const char *)&reuse, sizeof(reuse)
    );
    if (rc == 0 && check(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(sock);
    sock = -1;
  }

  freeaddrinfo(results);
  if (rp == NULL) return -1;
  return sock;
}

static int chatbot_accept_connection(
  int server_socket, struct sockaddr_in *address
) {
  int addrlen = sizeof(*address);
  int client_socket = accept(
    server_socket, (struct sockaddr *)address, (socklen_t*)&addrlen
  );
  if (client_socket < 0) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) return 0;
    return -1;
  }
  if (set_non_blocking(client_socket)) {
    close(client_socket);
    return -1;
  }
  return client_socket;
}

int chatbot_server() {
  int server_socket, client_socket, max_sd, activity, i;
  struct sockaddr_in address;
  fd_set read_fds, active_fd_set;
  char port[8] = {0};

  if (snprintf(port, sizeof(port) - 1, "%d", CHATBOT_PORT) <= 0) {
    exit(EXIT_FAILURE);
  }

  server_socket = chatbot_create_socket(NULL, port, bind);
  if (server_socket <= 0) {
    #ifndef NDEBUG
    perror("Socket failed");
    #endif
    exit(EXIT_FAILURE);
  }

  if (listen(server_socket, 3) < 0) {
    #ifndef NDEBUG
    perror("Listen failed");
    #endif
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  if (set_non_blocking(server_socket)) {
    #ifndef NDEBUG
    perror("set_non_blocking");
    #endif
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  if (loadResponses()) {
    #ifdef NDEBUG
    printf("Failed to load chat data\n");
    #endif
  }

  printf("Chatbot server started on port %d\n", CHATBOT_PORT);

  FD_ZERO(&active_fd_set);
  FD_SET(server_socket, &active_fd_set);
  max_sd = server_socket;

  while (1) {
    read_fds = active_fd_set;

    activity = select(max_sd + 1, &read_fds, NULL, NULL, NULL);

    if ((activity < 0) && (errno != EINTR)) {
      #ifndef NDEBUG
      perror("Select error");
      #endif
    }

    if (FD_ISSET(server_socket, &read_fds)) {
      client_socket = chatbot_accept_connection(server_socket, &address);
      if (client_socket < 0) {
        #ifndef NDEBUG
        perror("Accept failed");
        #endif
        break;
      }
      #ifndef NDEBUG
      printf(
        "New connection from %s:%d\n", inet_ntoa(address.sin_addr),
        ntohs(address.sin_port)
      );
      #endif

      FD_SET(client_socket, &active_fd_set);
      if (client_socket > max_sd) {
        max_sd = client_socket;
      }
      const char *resp = greetUser();
      if (sendJSONResponse(client_socket, resp) < 0) {
        close(client_socket);
        FD_CLR(client_socket, &active_fd_set);
      }
    }

    for (i = 0; i <= max_sd; i++) {
      if (FD_ISSET(i, &read_fds)) {
        if (handleClientMessage(i) < 0) {
          close(i);
          FD_CLR(i, &active_fd_set);
        }
      }
    }
  }

  for (i = 0; i <= max_sd; i++) {
    if (FD_ISSET(i, &active_fd_set)) {
      close(i);
      FD_CLR(i, &active_fd_set);
    }
  }

  return 0;
}

int chatbot_client() {
  int client_socket, flag = 1;
  fd_set read_fds;
  char buffer[BUFFER_SIZE];

  if (snprintf(buffer, sizeof(buffer) - 1, "%d", CHATBOT_PORT) <= 0) {
    exit(EXIT_FAILURE);
  }

  client_socket = chatbot_create_socket("127.0.0.1", buffer, connect);
  if (client_socket <= 0) {
    #ifndef NDEBUG
    perror("Socket creation failed");
    #endif
    exit(EXIT_FAILURE);
  }

  if (set_non_blocking(client_socket)) {
    #ifndef NDEBUG
    perror("set_non_blocking");
    #endif
    close(client_socket);
    return -1;
  }

  setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(flag));

  #ifndef NDEBUG
  printf("Connected to the server at 127.0.0.1:%d\n", CHATBOT_PORT);
  #endif

  while (1) {
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(client_socket, &read_fds);

    int max_sd = client_socket;

    int activity = select(max_sd + 1, &read_fds, NULL, NULL, NULL);

    if ((activity < 0) && (errno != EINTR)) {
      #ifndef NDEBUG
      perror("Select error");
      #endif
    }

    if (FD_ISSET(client_socket, &read_fds)) {
      if (handleServerResponse(client_socket) < 0) break;
    }

    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
      memset(buffer, 0, sizeof(buffer));
      if (!fgets(buffer, sizeof(buffer), stdin)) {
        break;
      }
      buffer[strcspn(buffer, "\n")] = 0;
      if (send_message(client_socket, buffer) < 0) break;
    }
  }

  close(client_socket);
  return 0;
}
