#ifndef CBUF_H
#define CBUF_H

#include <netdb.h>

// Circular buffer
typedef struct {
	pthread_mutex_t *lock;
	char *name;
	int size;			/* Buffer size, must be (bufsize % 1316) == 0 */
	int pos;			/* Up to where the buffer is filled */
	int writepos;		/* Up to where the buffer is get */
	void *buffer;		/* The buffer data */
	uint64_t input;
	uint64_t output;
	int pos_wrapped;
	int debug_get;
} CBUF;

CBUF *cbuf_init(int buffer_size, char *name);
void cbuf_free(CBUF **buffer);

int  cbuf_fill(CBUF *b, uint8_t *data, int datasize);
void *cbuf_get(CBUF *b, int size, int *ret_datasize);
void *cbuf_peek(CBUF *b, int size, int *ret_datasize);
void cbuf_copy(CBUF *src, CBUF *dest);

int cbuf_data_size(CBUF *b);

void cbuf_poison(CBUF *b, char poison_byte);

void cbuf_dump(CBUF *b);

#endif
