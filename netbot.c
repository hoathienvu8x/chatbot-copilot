#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "netbot.h"
#include "chatbot.h"
#include "cJSON.h"

#define CHATBOT_PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

static int sendJSONResponse(int client_socket, const char *message) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "response", message);
    #ifndef NDEBUG
    const char *json_response = cJSON_Print(response);
    #else
    const char *json_response = cJSON_PrintUnformatted(response);
    #endif
    int ret = write(client_socket, json_response, strlen(json_response));
    cJSON_Delete(response);
    free((void *)json_response);
    if (ret <= 0) return -1;
    return 0;
}

static int handleClientMessage(int client_socket) {
  char buffer[BUFFER_SIZE];
  int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
  if (bytes_read <= 0) {
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
  if (chatbot_strcasestr(buffer, "bye") != NULL || chatbot_strcasestr(buffer, "exit") != NULL) {
    return -1;
  }
  return 0;
}

static int handleServerResponse(int server_socket) {
  char buffer[BUFFER_SIZE];
  int bytes_read = read(server_socket, buffer, sizeof(buffer) - 1);
  if (bytes_read <= 0) {
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

int chatbot_server() {
  int server_socket, client_socket, max_sd, activity, i, reuse = 1;
  struct sockaddr_in address;
  fd_set read_fds, active_fd_set;

  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket == 0) {
    #ifndef NDEBUG
    perror("Socket failed");
    #endif
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(CHATBOT_PORT);

  if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
    #ifndef NDEBUG
    perror("setsockopt failed");
    #endif
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
    #ifndef NDEBUG
    perror("Bind failed");
    #endif
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  if (listen(server_socket, 3) < 0) {
    #ifndef NDEBUG
    perror("Listen failed");
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
      int addrlen = sizeof(address);
      client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
      if (client_socket < 0) {
        #ifndef NDEBUG
        perror("Accept failed");
        #endif
        break;
      }
      #ifndef NDEBUG
      printf("New connection from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
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
  int client_socket, reuse = 1;
  struct sockaddr_in server_address;
  fd_set read_fds;
  char buffer[BUFFER_SIZE];

  client_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (client_socket < 0) {
    #ifndef NDEBUG
    perror("Socket creation failed");
    #endif
    exit(EXIT_FAILURE);
  }

  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(CHATBOT_PORT);
  if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
    #ifndef NDEBUG
    perror("Invalid address or address not supported");
    #endif
    close(client_socket);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
    #ifndef NDEBUG
    perror("setsockopt failed");
    #endif
    close(client_socket);
    exit(EXIT_FAILURE);
  }

  if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
    #ifndef NDEBUG
    perror("Connection failed");
    #endif
    close(client_socket);
    exit(EXIT_FAILURE);
  }
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

    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
      memset(buffer, 0, sizeof(buffer));
      if (!fgets(buffer, sizeof(buffer), stdin)) {
        break;
      }
      buffer[strcspn(buffer, "\n")] = 0;
      if (send(client_socket, buffer, strlen(buffer), 0) < 0) break;
    }

    if (FD_ISSET(client_socket, &read_fds)) {
      if (handleServerResponse(client_socket) < 0) break;
    }
  }

  close(client_socket);
  return 0;
}
