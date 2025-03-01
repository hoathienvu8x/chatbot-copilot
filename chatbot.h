#ifndef _CHATBOT_H
#define _CHATBOT_H

const char * greetUser();
const char * handleInput(char *input);
int loadResponses();
int chatbot_strcasecmp(const char *_l, const char *_r);
int chatbot_strncasecmp(const char *_l, const char *_r, size_t n);
char *chatbot_strcasestr(const char *h, const char *n);

#endif
