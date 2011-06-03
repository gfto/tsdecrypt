#ifndef CAMD_H
#define CAMD_H

#include "data.h"

int camd35_connect		(struct camd35 *c);
void camd35_disconnect	(struct camd35 *c);

int camd35_send_ecm		(struct camd35 *c, uint16_t service_id, uint16_t ca_id, uint16_t idx, uint8_t *data, uint8_t data_len);
int camd35_send_emm		(struct camd35 *c, uint16_t ca_id, uint8_t *data, uint8_t data_len);

#endif
