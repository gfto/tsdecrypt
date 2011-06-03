#ifndef TABLE_H
#define TABLES_H

#include "data.h"

void process_pat(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_cat(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_pmt(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_emm(struct ts *ts, uint16_t pid, uint8_t *ts_packet);
void process_ecm(struct ts *ts, uint16_t pid, uint8_t *ts_packet);

#endif
