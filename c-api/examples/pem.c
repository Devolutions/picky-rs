#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <picky.h>

enum {
  FILE_CONTENT_BUF_SIZE = 8096,
};

void print_picky_error(char const *desc) {
  int buf_sz = picky_last_error_length_utf8();

  if (buf_sz == 0) {
    printf("Warning: attempted to print picky error, but there is no last "
           "error registered (%s)",
           desc);
    return;
  }

  char *buf = (char *)calloc(buf_sz, sizeof(char));

  if (picky_error_message_utf8(buf, buf_sz) > 0) {
    printf("%s: %s\n", desc, buf);
  } else {
    printf("%s: an error occurred.\n", desc);
  }

  free(buf);
}

int main(int argc, char **argv) {
  int exit_status = EXIT_FAILURE;

  FILE *pem_file = NULL;
  char pem_file_content[FILE_CONTENT_BUF_SIZE] = {0};
  picky_pem_t *pem = NULL;
  char *pem_label = NULL;
  int pem_label_sz = 0;
  uint8_t *pem_data = NULL;
  int pem_data_sz = 0;

  if (argc < 2) {
    printf("Please, provide a path to a PEM file.\n");
    goto exit;
  }

  pem_file = fopen(argv[1], "r");
  if (pem_file == NULL) {
    printf("Couldn't open PEM file: errno %d.\n", errno);
    goto exit;
  }

  fread(pem_file_content, sizeof(uint8_t), FILE_CONTENT_BUF_SIZE, pem_file);
  if (ferror(pem_file) != 0) {
    printf("Couldn't read PEM file: errno %d.\n", errno);
    goto exit;
  }

  pem = picky_pem_parse(pem_file_content, FILE_CONTENT_BUF_SIZE);
  if (pem == NULL) {
    print_picky_error("picky_pem_parse");
    goto exit;
  }

  pem_label_sz = picky_pem_label_length(pem);
  pem_label = (char *)calloc(pem_label_sz, sizeof(char));
  if (picky_pem_label(pem, pem_label, pem_label_sz) != pem_label_sz) {
    print_picky_error("picky_pem_label");
    goto exit;
  }

  pem_data_sz = picky_pem_data_length(pem);
  pem_data = (uint8_t *)calloc(pem_data_sz, sizeof(uint8_t));
  if (picky_pem_data(pem, pem_data, pem_data_sz) != pem_data_sz) {
    print_picky_error("picky_pem_data");
    goto exit;
  }

  printf("label=%s\nlen=%d\n", pem_label, pem_data_sz);

  exit_status = EXIT_SUCCESS;

exit:
  if (pem_file != NULL) {
    fclose(pem_file);
    pem_file = NULL;
  }

  if (pem_label != NULL) {
    free(pem_label);
    pem_label = NULL;
  }

  if (pem_data != NULL) {
    free(pem_data);
    pem_data = NULL;
  }

  if (pem != NULL) {
    picky_pem_drop(pem);
    pem = NULL;
  }

  return exit_status;
}
