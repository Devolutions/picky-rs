#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum picky_status {
  PICKY_STATUS_SUCCESS = 0,
  PICKY_STATUS_FAILURE = -1,
} picky_status;

/**
 * Opaque type for picky PEM object.
 */
typedef struct picky_pem_t picky_pem_t;

void picky_clear_last_error(void);

int picky_last_error_length_utf8(void);

int picky_last_error_length_utf16(void);

int picky_error_message_utf8(char *buf, int buf_sz);

int picky_error_message_utf16(uint16_t *buf, int buf_sz);

/**
 * Parses a PEM-encoded string representation into a PEM object.
 */
struct picky_pem_t *picky_pem_parse(const char *input);

/**
 * Creates a PEM object with a copy of the data.
 */
struct picky_pem_t *picky_pem_new(const uint8_t *data, int data_sz, const char *label);

/**
 * Encodes to PEM string without copying the payload.
 */
enum picky_status picky_encode_pem(const uint8_t *data,
                                   int data_sz,
                                   const char *label,
                                   char *repr,
                                   int repr_sz);

/**
 * Copy raw data contained in the PEM object.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_pem_data(const struct picky_pem_t *this_, uint8_t *data, int data_sz);

/**
 * Copy the label associated to the data contained in the PEM object.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_pem_label(const struct picky_pem_t *this_, char *label, int label_sz);

/**
 * Encodes PEM object to the PEM string representation.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_pem_to_string(const struct picky_pem_t *this_, char *repr, int repr_sz);

/**
 * Frees memory for this PEM object.
 */
void picky_pem_drop(struct picky_pem_t*);

/**
 * Returns a cloned version of this PEM object.
 */
struct picky_pem_t *picky_pem_clone(const struct picky_pem_t *src);
