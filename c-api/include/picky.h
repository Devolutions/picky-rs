#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Picky return status
 */
typedef enum picky_status {
  /**
   * Operation ended successfully.
   */
  PICKY_STATUS_SUCCESS = 0,
  /**
   * If a function returns this value,
   * a detailed error message can be retrieved using `picky_error_message_utf*`.
   */
  PICKY_STATUS_FAILURE = -1,
} picky_status;

/**
 * Opaque type for picky PEM object.
 */
typedef struct picky_pem_t picky_pem_t;

/**
 * Clear the LAST_ERROR static.
 */
void picky_clear_last_error(void);

/**
 * Get the length of the last error message in bytes when encoded as UTF-8, including the trailing null.
 */
int picky_last_error_length_utf8(void);

/**
 * Get the length of the last error message in bytes when encoded as UTF-16, including the trailing null.
 */
int picky_last_error_length_utf16(void);

/**
 * Peek at the most recent error and write its error message into the provided buffer as a UTF-8 encoded string.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_error_message_utf8(char *buf,
                             int buf_sz);

/**
 * Peek at the most recent error and write its error message into the provided buffer as a UTF-16 encoded string.
 *
 * Returns the number of elements written, or `-1` if there was an error.
 */
int picky_error_message_utf16(uint16_t *buf,
                              int buf_sz);

/**
 * Parses a PEM-encoded string representation into a PEM object.
 */
struct picky_pem_t *picky_pem_parse(const char *input, int input_sz);

/**
 * Creates a PEM object with a copy of the data.
 */
struct picky_pem_t *picky_pem_new(const uint8_t *data,
                                  int data_sz,
                                  const char *label,
                                  int label_sz);

/**
 * Encodes to PEM string without copying the payload.
 */
enum picky_status picky_encode_pem(const uint8_t *data,
                                   int data_sz,
                                   const char *label,
                                   int label_sz,
                                   char *repr,
                                   int repr_sz);

/**
 * Get the length of the pem data in bytes.
 *
 * Returns the number of required bytes, or `-1` if there was an error.
 */
int picky_pem_data_length(const struct picky_pem_t *this_);

/**
 * Copy raw data contained in the PEM object.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_pem_data(const struct picky_pem_t *this_, uint8_t *data, int data_sz);

/**
 * Get the length of the pem label in bytes when encoded as UTF-8, including the trailing null.
 *
 * Returns the number of required bytes, or `-1` if there was an error.
 */
int picky_pem_label_length(const struct picky_pem_t *this_);

/**
 * Copy the label associated to the data contained in the PEM object.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_pem_label(const struct picky_pem_t *this_, char *label, int label_sz);

/**
 * Compute the length of the PEM representation, including the trailing null.
 *
 * Returns the number of required bytes, or `-1` if there was an error.
 */
int picky_pem_compute_repr_length(const struct picky_pem_t *this_);

/**
 * Encodes PEM object to the PEM string representation.
 *
 * Returns the number of bytes written, or `-1` if there was an error.
 */
int picky_pem_to_repr(const struct picky_pem_t *this_, char *repr, int repr_sz);

/**
 * Frees memory for this PEM object.
 */
void picky_pem_drop(struct picky_pem_t*);

/**
 * Returns a cloned version of this PEM object.
 */
struct picky_pem_t *picky_pem_clone(const struct picky_pem_t *src);
