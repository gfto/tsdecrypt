#ifndef CAMD_H
#define CAMD_H

#include <inttypes.h>

int camd35_connect();
void camd35_disconnect();

int camd35_send_ecm(uint16_t service_id, uint16_t ca_id, uint16_t idx, uint8_t *data, uint8_t data_len);
int camd35_send_emm(uint16_t ca_id, uint8_t *data, uint8_t data_len);

#endif
