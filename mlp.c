#include "mlp.h"
#include <stdlib.h>
#include <math.h>

void initialize_mlp(MLP *mlp, int input_size, int hidden_size, int output_size) {
  mlp->input_size = input_size;
  mlp->hidden_size = hidden_size;
  mlp->output_size = output_size;

  mlp->input_hidden_weights = (float *)malloc(input_size * hidden_size * sizeof(float));
  mlp->hidden_output_weights = (float *)malloc(hidden_size * output_size * sizeof(float));
  mlp->hidden_biases = (float *)malloc(hidden_size * sizeof(float));
  mlp->output_biases = (float *)malloc(output_size * sizeof(float));

  if (
    !mlp->input_hidden_weights || !mlp->hidden_output_weights ||
    !mlp->hidden_biases || mlp->output_biases
  ) {
    return -1;
  }

  // Initialize weights and biases with random values
  for (int i = 0; i < input_size * hidden_size; i++) {
    mlp->input_hidden_weights[i] = ((float)rand() / RAND_MAX) * 2 - 1;
  }
  for (int i = 0; i < hidden_size * output_size; i++) {
    mlp->hidden_output_weights[i] = ((float)rand() / RAND_MAX) * 2 - 1;
  }
  for (int i = 0; i < hidden_size; i++) {
    mlp->hidden_biases[i] = ((float)rand() / RAND_MAX) * 2 - 1;
  }
  for (int i = 0; i < output_size; i++) {
    mlp->output_biases[i] = ((float)rand() / RAND_MAX) * 2 - 1;
  }
  return 0;
}

void dispose_mlp(MLP *mlp) {
  if (mlp->input_hidden_weights) free(mlp->input_hidden_weights);
  if (mlp->hidden_output_weights) free(mlp->hidden_output_weights);
  if (mlp->hidden_biases) free(mlp->hidden_biases);
  if (mlp->output_biases) free(mlp->output_biases);
}

int forward(MLP *mlp, float *input, float *hidden_layer, float *output_layer) {
  if (
    !mlp->input_hidden_weights || !mlp->hidden_output_weights ||
    !mlp->hidden_biases || mlp->output_biases
  ) {
    return -1;
  }
  // Input to hidden layer
  for (int i = 0; i < mlp->hidden_size; i++) {
    hidden_layer[i] = mlp->hidden_biases[i];
    for (int j = 0; j < mlp->input_size; j++) {
      hidden_layer[i] += input[j] * mlp->input_hidden_weights[j * mlp->hidden_size + i];
    }
    hidden_layer[i] = tanh(hidden_layer[i]);
  }

  // Hidden to output layer
  for (int i = 0; i < mlp->output_size; i++) {
    output_layer[i] = mlp->output_biases[i];
    for (int j = 0; j < mlp->hidden_size; j++) {
      output_layer[i] += hidden_layer[j] * mlp->hidden_output_weights[j * mlp->output_size + i];
    }
  }

  // Softmax activation
  float sum = 0.0;
  for (int i = 0; i < mlp->output_size; i++) {
    output_layer[i] = exp(output_layer[i]);
    sum += output_layer[i];
  }
  for (int i = 0; i < mlp->output_size; i++) {
    output_layer[i] /= sum;
  }
  return 0;
}

int argmax(float *array, int size) {
  int max_index = 0;
  if (!array) return -1;
  for (int i = 1; i < size; i++) {
    if (array[i] > array[max_index]) {
      max_index = i;
    }
  }
  return max_index;
}
