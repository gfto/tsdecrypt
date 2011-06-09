#ifndef PROCESS_H
#define PROCESS_H

void *decode_thread(void *_ts);
void *write_thread(void *_ts);
void process_packets(struct ts *ts, uint8_t *data, ssize_t data_len);

#endif
