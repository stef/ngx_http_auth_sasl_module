#ifndef sasl_header_parser_h
#define sasl_header_parser_h

#include <stdlib.h>

typedef struct {
  const char *realm;
  size_t realm_len;
  const char *mech;
  size_t mech_len;
  unsigned long s2s;
  const char *c2s;
  size_t c2s_len;
  const char *s2c;
  size_t *s2c_len;
  const char* input;
  size_t input_len;
  size_t input_ptr;
} sasl_header_fields_t;


void parse_header(sasl_header_fields_t *auxil, const unsigned char* header, const size_t header_len);

#endif // sasl_header_parser_h
