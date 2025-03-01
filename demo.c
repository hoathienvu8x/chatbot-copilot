#include <stdio.h>
#include <string.h>
#include "chatbot.h"

#define MAX_INPUT 256

int main() {
  char input[MAX_INPUT];

  greetUser();

  while (1) {
    printf("> ");
    if (!fgets(input, MAX_INPUT, stdin)) break;

    // Remove newline character from input
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, "bye") == 0 || strcmp(input, "exit") == 0) {
      handleInput(input);
      break;
    }

    handleInput(input);
  }

  return 0;
}
