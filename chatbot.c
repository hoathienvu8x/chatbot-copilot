#include <stdio.h>
#include <string.h>
#include "chatbot.h"

void greetUser() {
  printf("Hello! I am a simple chatbot created in C. How can I help you today?\n");
}

void handleInput(char *input) {
  if (strstr(input, "hello") != NULL || strstr(input, "hi") != NULL) {
    printf("Hi there! How can I assist you?\n");
  } else if (strstr(input, "how are you") != NULL) {
    printf("I'm just a program, so I don't have feelings, but thanks for asking!\n");
  } else if (strstr(input, "what is your name") != NULL) {
    printf("I am a C chatbot. Nice to meet you!\n");
  } else if (strstr(input, "bye") != NULL || strstr(input, "exit") != NULL) {
    printf("Goodbye! Have a great day!\n");
  } else {
    printf("I'm sorry, I don't understand that. Can you ask something else?\n");
  }
}


