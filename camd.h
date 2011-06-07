#ifndef CAMD_H
#define CAMD_H

#include "data.h"

struct camd_msg *		camd_msg_alloc_emm	(uint16_t ca_id, uint8_t *emm_data, uint8_t emm_data_len);
struct camd_msg *		camd_msg_alloc_ecm	(uint16_t ca_id, uint16_t service_id, uint16_t idx, uint8_t *ecm_data, uint8_t ecm_data_len);
void					camd_msg_free   	(struct camd_msg **pmsg);

void					camd_start			(struct ts *ts);
void					camd_stop			(struct ts *ts);
void					camd_msg_process	(struct ts *ts, struct camd_msg *msg);

#endif
