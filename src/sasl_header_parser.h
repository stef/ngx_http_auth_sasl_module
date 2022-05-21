#ifndef sasl_header_parser_h
#define sasl_header_parser_h

#include <stdlib.h>

typedef struct {
  char *realm;
  char *mech;
  unsigned long s2s;
  char *c2s;
  char *s2c;
  const char* input;
  size_t input_len;
  size_t input_ptr;
} sasl_header_fields_t;


void parse_header(sasl_header_fields_t *auxil, const unsigned char* header, const size_t header_len);
void clear_parsed(sasl_header_fields_t *auxil);

#endif // sasl_header_parser_h
