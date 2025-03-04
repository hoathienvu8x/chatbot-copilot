#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define FIN_BIT 0x80
#define OPCODE_CONTINUATION 0x00
#define OPCODE_TEXT 0x01

void create_websocket_frame(
  const uint8_t *message, size_t message_len, uint8_t **frames,
  size_t *frames_len, size_t chunk_size
) {
  size_t num_frames = (message_len + chunk_size - 1) / chunk_size;
  *frames_len = 0;

  // Allocate memory for all frames
  *frames = (uint8_t *)malloc(num_frames * (chunk_size + 10)); // Allocating worst case scenario for each frame

  size_t offset = 0;
  for (size_t i = 0; i < num_frames; i++) {
    uint8_t fin = (i == num_frames - 1) ? FIN_BIT : 0;
    uint8_t opcode = (i == 0) ? OPCODE_TEXT : OPCODE_CONTINUATION;
    size_t frame_len = (i == num_frames - 1) ? (message_len - offset) : chunk_size;
    size_t header_len;

    if (frame_len <= 125) {
      header_len = 2;
    } else if (frame_len <= 65535) {
      header_len = 4;
    } else {
      header_len = 10;
    }

    (*frames)[*frames_len] = fin | opcode;

    if (frame_len <= 125) {
      (*frames)[*frames_len + 1] = frame_len;
    } else if (frame_len <= 65535) {
      (*frames)[*frames_len + 1] = 126;
      (*frames)[*frames_len + 2] = (frame_len >> 8) & 0xFF;
      (*frames)[*frames_len + 3] = frame_len & 0xFF;
    } else {
      (*frames)[*frames_len + 1] = 127;
      for (int j = 0; j < 8; ++j) {
        (*frames)[*frames_len + 9 - j] = frame_len & 0xFF;
        frame_len >>= 8;
      }
    }

    memcpy(*frames + *frames_len + header_len, message + offset, frame_len);
    *frames_len += header_len + frame_len;
    offset += frame_len;
  }
}

void free_websocket_frames(uint8_t *frames) {
  free(frames);
}

int main() {
  const char *message =
    "This is a large message that needs to be split into multiple WebSocket frames using continuation frames. "
    "This ensures that the framing process handles multi-part messages correctly. "
    "The message is split into chunks and each chunk is framed separately.";
  size_t message_len = strlen(message);
  uint8_t *frames;
  size_t frames_len;
  size_t chunk_size = 20; // Example chunk size

  create_websocket_frame(
    (const uint8_t *)message, message_len, &frames, &frames_len, chunk_size
  );

  // Print the frames in hexadecimal format for verification
  for (size_t i = 0; i < frames_len; i++) {
    // printf("%02X ", frames[i]);
    printf("%s\n", frames[i]);
  }
  printf("\n");

  free_websocket_frames(frames);

  return 0;
}
