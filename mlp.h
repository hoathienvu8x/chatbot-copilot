#ifndef _MLP_H
#define _MLP_H

typedef struct {
  int input_size;
  int hidden_size;
  int output_size;
  float *input_hidden_weights;
  float *hidden_output_weights;
  float *hidden_biases;
  float *output_biases;
} MLP;

int initialize_mlp(MLP *mlp, int input_size, int hidden_size, int output_size);
void dispose_mlp(MLP *mlp);
int forward(MLP *mlp, float *input, float *hidden_layer, float *output_layer);
int argmax(float *array, int size);

#endif
