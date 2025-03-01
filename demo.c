#include <string.h>
#include "netbot.h"

int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1],"c") != 0) {
    return chatbot_server();
  }
  return chatbot_client();
}
