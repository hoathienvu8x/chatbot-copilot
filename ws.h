#ifndef _WS_H
#define _WS_H

int generate_random_websocket_key(char *output);
int generate_websocket_handshake_key(const char *key, char *output);

#endif
