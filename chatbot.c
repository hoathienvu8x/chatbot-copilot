#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chatbot.h"
#include "cJSON.h"

#define CHATBOT_DB "responses.json"

cJSON *responses = NULL;

const char * greetUser() {
  return "Hello! I am a simple chatbot created in C. How can I help you today?\0";
}

const char * handleInput(char *input) {
  cJSON *el;
  cJSON_ArrayForEach(el, responses) {
    if (!cJSON_IsObject(el)) continue;
    if (!cJSON_HasObjectItem(el, "tags") || !cJSON_HasObjectItem(el, "answer")) {
      continue;
    }
    cJSON *tags = cJSON_GetObjectItem(el, "tags");
    if (!cJSON_IsArray(tags) || cJSON_GetArraySize(tags) == 0) continue;
    cJSON *it;
    cJSON_ArrayForEach(it, tags) {
      const char *tag = cJSON_GetStringValue(it);
      if (!tag || chatbot_strcasestr(input, tag) == NULL) continue;
      cJSON *answer = cJSON_GetObjectItem(el, "answer");
      return cJSON_GetStringValue(answer);
    }
  }
  return "I'm sorry, I don't understand that. Can you ask something else?\0";
}

int loadResponses() {
  FILE *file = fopen(CHATBOT_DB, "r");
  if (!file) {
    #ifndef NDEBUG
    perror("Failed to open responses file");
    #endif
    return -1;
  }

  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *data = (char *)malloc(length + 1);
  if (data) {
    if (fread(data, 1, length, file) == 0) {
      #ifndef NDEBUG
      fprintf(stderr, "fread failed\n");
      #endif
      free(data);
      fclose(file);
      return -1;
    }
    data[length] = '\0';
  }
  fclose(file);

  responses = cJSON_Parse(data);
  free(data);

  if (!responses) {
    #ifndef NDEBUG
    fprintf(stderr, "Error parsing JSON: %s\n", cJSON_GetErrorPtr());
    #endif
    return -1;
  }

  if (!cJSON_IsArray(responses)) {
    #ifndef NDEBUG
    fprintf(stderr, "Invalid reponses struct");
    #endif
    cJSON_free(responses);
  }

  return 0;
}

int chatbot_strcasecmp(const char *_l, const char *_r) {
  const unsigned char *l = (void *)_l, *r = (void *)_r;
  unsigned char flipbit = ~(1 << 5);
  for (; *l && *r && (*l == *r || (*l & flipbit) == (*r & flipbit)); l++,r++);
  return (*l & flipbit) - (*r & flipbit);
}


int chatbot_strncasecmp(const char *_l, const char *_r, size_t n) {
  const unsigned char *l = (void *)_l, *r = (void *)_r;
  if (!n--) return 0;
  unsigned char flipbit = ~(1 << 5);
  for (; *l && *r && n && (*l == *r || (*l & flipbit) == (*r & flipbit)); l++, r++,n--);
  return (*l & flipbit) - (*r & flipbit);
}

char *chatbot_strcasestr(const char *h, const char *n) {
	size_t l = strlen(n);
	for (; *h; h++) if (!chatbot_strncasecmp(h, n, l)) return (char *)h;
	return 0;
}
