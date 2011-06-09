#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>

#include "libfuncs/libfuncs.h"

#include "cbuf.h"

static void cbuf_lock(CBUF *b) {
	pthread_mutex_lock(b->lock);
}

static void cbuf_unlock(CBUF *b) {
	pthread_mutex_unlock(b->lock);
}

/* Returns how much data is filled in the buffer */
int cbuf_free_data_size(CBUF *b) {
	int ret = b->size - (b->input - b->output);
	assert(ret >= 0);
	return ret;
}

void cbuf_dump(CBUF *b) {
	LOGf("CBUF  [%10s]: size:%d pos:%d writepos:%d input:%llu output:%llu free_data:%d buffered:%lld\n",
		b->name,
		b->size,
		b->pos,
		b->writepos,
		b->input,
		b->output,
		cbuf_free_data_size(b),
		b->input - b->output
	);
/*
	char *z = b->buffer;
	printf("cbuf(%s), dump:", b->name);
	int i;
	for (i=0;i<b->size;i++) {
		printf("%c", z[i]);
	}
	printf("\n\n");
*/
}

CBUF *cbuf_init(int buffer_size, char *name) {
	CBUF *b = calloc(1, sizeof(CBUF));
	if (!b)
		return NULL;
	if (!buffer_size)
		return 0;
	pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
	if (pthread_mutex_init(mutex, NULL) != 0) {
		perror("cbuf_new: mutex_init");
		return NULL;
	}
	b->lock     = mutex;
	b->name     = strdup(name);
	b->size     = buffer_size;
	b->pos      = 0;
	b->writepos = 0;
	b->buffer   = calloc(1, buffer_size);
	if (!b->buffer) {
		free(b);
		LOGf("CBUF  [%10s]: Can't allocate buffer size: %d\n", name, buffer_size);
		return NULL;
	}
	return b;
}

void cbuf_free(CBUF **pb) {
	CBUF *b = *pb;
	if (!b)
		return;
	pthread_mutex_destroy(b->lock);
	FREE(b->lock);
	FREE(b->buffer);
	FREE(b->name);
	FREE(*pb);
}

// Returns -1 on buffer wrap around
int cbuf_fill(CBUF *b, uint8_t *data, int datasize) {
	int ret = 0;
	cbuf_lock(b);
//	LOGf("  cbuf_fill(%s, '%s', %d)\n", b->name, data, datasize);
//	cbuf_dump(b);
	assert(datasize <= b->size);
	int to_copy = min(datasize, (b->size - b->pos));
	if (!to_copy || !data) {
		LOGf("CBUF [%10s]: Nothing to fill.\n", b->name);
		ret = -2;
		goto OUT;
	}
	if (cbuf_free_data_size(b)-to_copy <= 0) {
//		LOGf("CBUF [%10s]: Buffer will wrap by (%d bytes). Data not filled, consume more!\n", b->name, -(cbuf_free_data_size(b)-to_copy));
//		cbuf_dump(b);
//		b->debug_get = 1;
		ret = -1;
		goto OUT;
	}
	memcpy(b->buffer + b->pos, data, to_copy);
	int copied = to_copy;
	b->pos   += copied; // Move current buffer position
	b->input += copied;
	assert(b->pos <= b->size);
	if (b->pos == b->size) { // Buffer wrap around
		b->pos = 0;
	}
	if (copied < datasize) { // Move the rest
//		Logs when wrapping
//		LOGf("cbuf(%10s) copied < datasize, copied:%d datasize:%d datasize-copied: %d pos:%d\n",
//			b->name, copied, datasize, datasize - copied, b->pos);
//		cbuf_dump(b);
		cbuf_unlock(b);
		ret = cbuf_fill(b, data + copied, datasize - copied);
		goto OUT;
	}

OUT:
	cbuf_unlock(b);
	return ret;
}





/* Returns how much space is left to the end of the buffer */
static int cbuf_size_to_end(CBUF *b) {
	int ret = b->input - b->output;
	if (b->writepos + ret > b->size) {
		ret = b->size - b->writepos;
	}
	return ret;
}

int cbuf_data_size(CBUF *b) {
	return cbuf_size_to_end(b);
}

void *cbuf_get(CBUF *b, int size, int *ret_datasize) {
	cbuf_lock(b);
	void *ret = NULL;
	int new_size = min(size, cbuf_size_to_end(b));
	if (b->debug_get) {
		LOGf("1 cbuf_get(%s, %d) new_size: %d size_to_end: %d\n",
				b->name, size, new_size, cbuf_size_to_end(b));
		cbuf_dump(b);
	}
	if (new_size <= 0) { // No data
		*ret_datasize = 0;
		ret = NULL;
		goto OUT;
	}
	*ret_datasize = new_size;
	ret = b->buffer + b->writepos;
	b->writepos += new_size; // Move writepos
	b->output   += new_size;
	if (b->writepos > b->size) {
		LOGf("!!! b->writepos > b->size !!! size:%d new_size:%d\n", size, new_size);
		cbuf_dump(b);
		assert(b->writepos <= b->size);
	}
	if (b->writepos == b->size) // Buffer wraparound
		b->writepos = 0;

OUT:
	if (b->debug_get) {
		LOGf("2 cbuf_get(%s, %d) new_size: %d size_to_end: %d ret_sz:%d\n",
				b->name, size, new_size, cbuf_size_to_end(b), *ret_datasize);
		cbuf_dump(b);
		b->debug_get = 0;
	}
	cbuf_unlock(b);
	return ret;
}

void *cbuf_peek(CBUF *b, int size, int *ret_datasize) {
	cbuf_lock(b);
	void *ret = NULL;
	int new_size = min(size, cbuf_size_to_end(b));

	if (new_size <= 0) { // No data
		*ret_datasize = 0;
		ret = NULL;
		goto OUT;
	}
	*ret_datasize = new_size;
	ret = b->buffer + b->writepos;

OUT:
	cbuf_unlock(b);
	return ret;
}

void cbuf_copy(CBUF *from, CBUF *to) {
//	LOGf("cbuf_copy(%s, %s)\n", from->name, to->name);
	int data_size;
	void *data;
	do {
		data = cbuf_get(from, from->input - from->output, &data_size);
		if (from->debug_get)
			LOGf("copied from %s to %s size=%d\n", from->name, to->name, data_size);
		if (!data || data_size <= 0)
			break;
		cbuf_fill(to, data, data_size);
	} while (1);
}

void cbuf_poison(CBUF *b, char poison_byte) {
	memset(b->buffer, poison_byte, b->size);
}


/*
void consume(CBUF *b, int size) {
	int data_size, i;
	char *data = cbuf_get(b, size, &data_size);
	if (data && data_size > 0) {
		printf("Consumed %d Data: \"", data_size);
		for (i=0;i<data_size;i++) {
			printf("%c", data[i]);
		}
		printf("\"\n");
	} else {
		printf("%s", "There is nothing to consume!\n");
	}
}

void cbuf_test() {
	CBUF *in;

	CBUF *out;
	out = cbuf_init(64, "out");
	cbuf_poison(out, 'O');
	cbuf_dump(out);

	in = cbuf_init(4, "in");
	cbuf_poison(in, '*');

	cbuf_fill(in, "12", 2);
	cbuf_fill(in, "34", 2);
	cbuf_fill(in, "z" , 1);
	cbuf_dump(in);

	cbuf_copy(in, out);
	cbuf_dump(out);
	consume(in, 16);
	cbuf_dump(in);

	cbuf_fill(in, "a", 1);
	cbuf_fill(in, "b", 1);
	cbuf_fill(in, "c", 1);
	cbuf_fill(in, "d", 1);
	cbuf_dump(in);

	cbuf_copy(in, out);
	cbuf_dump(out);

	consume(in, 4);
	cbuf_dump(in);

	cbuf_fill(in, "gfgf", 4);
	cbuf_dump(in);

	consume(in, 4);
	cbuf_dump(in);

	cbuf_fill(in, "r", 1);
	cbuf_fill(in, "r", 1);
	cbuf_fill(in, "r", 1);
	cbuf_fill(in, "r", 1);
	cbuf_dump(in);

	consume(out, 6);
	cbuf_copy(in, out);
	consume(out, 6);
	consume(out, 6);
	consume(out, 6);
	consume(out, 6);

	cbuf_free(in);
	cbuf_free(out);

}
*/
