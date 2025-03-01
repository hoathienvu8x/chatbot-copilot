#include <stdio.h>
#include <string.h>
#include "chatbot.h"

const char * greetUser() {
  return "Hello! I am a simple chatbot created in C. How can I help you today?\0";
}

const char * handleInput(char *input) {
  if (strstr(input, "hello") != NULL || strstr(input, "hi") != NULL) {
    return "Hi there! How can I assist you?\0";
  } else if (strstr(input, "how are you") != NULL) {
    return "I'm just a program, so I don't have feelings, but thanks for asking!\0";
  } else if (strstr(input, "what is your name") != NULL) {
    return "I am a C chatbot. Nice to meet you!\0";
  } else if (strstr(input, "bye") != NULL || strstr(input, "exit") != NULL) {
    return "Goodbye! Have a great day!\0";
  }
  return "I'm sorry, I don't understand that. Can you ask something else?\0";
}


