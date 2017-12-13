/*
 * Exec external program to notify for an event
 * Copyright (C) 2011 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License (COPYING file) for more details.
 *
 */

// Needed for asprintf
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "libfuncs/queue.h"

#include "notify.h"
#include "util.h"

struct npriv {
	char	ident[128];
	char	program[512];
	char	msg_id[64];
	char	text[256];
	char	input[128];
	char	output[128];
	time_t	ts;
	int		sync;			/* Wait for message to be delivered */
};

static void *do_notify(void *in) {
	struct npriv *data = in;
	struct npriv *shared = mmap(NULL, sizeof(struct npriv), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!shared) {
		perror("mmap");
		goto OUT;
	}
	*shared = *data;
	pid_t pid = fork();
	if (pid==0) { // child process
		char *args[] = { shared->program, shared->ident, NULL };
		int e = 0;
		unsigned int i, r;
		char **env = calloc(32, sizeof(char *));
		if (asprintf(&env[e++], "_TS=%ld"			, shared->ts) < 0) exit(EXIT_FAILURE);
		if (asprintf(&env[e++], "_IDENT=%s"			, shared->ident) < 0) exit(EXIT_FAILURE);
		if (asprintf(&env[e++], "_INPUT_ADDR=%s"	, shared->input) < 0) exit(EXIT_FAILURE);
		if (asprintf(&env[e++], "_OUTPUT_ADDR=%s"	, shared->output) < 0) exit(EXIT_FAILURE);
		if (asprintf(&env[e++], "_MESSAGE_ID=%s"	, shared->msg_id) < 0) exit(EXIT_FAILURE);
		if (asprintf(&env[e++], "_MESSAGE_TEXT=%s"	, shared->text) < 0) exit(EXIT_FAILURE);
		r = strlen(shared->msg_id);
		for (i=0; i<r; i++) {
			if (isalpha(shared->msg_id[i]))
				shared->msg_id[i] = tolower(shared->msg_id[i]);
			if (shared->msg_id[i] == '_')
				shared->msg_id[i] = ' ';
		}
		if (asprintf(&env[e++], "_MESSAGE_MSG=%s"	, shared->msg_id) < 0) exit(EXIT_FAILURE);
		execve(args[0], args, env);
		// We reach here only if there is an error.
		fprintf(stderr, "execve('%s') failed: %s!\n", args[0], strerror(errno));
		do {
			free(env[e--]);
		} while (e);
		free(env);
		exit(EXIT_FAILURE);
	} else if (pid < 0) {
		fprintf(stderr, "fork() failed: %s\n", strerror(errno));
	} else {
		waitpid(pid, NULL, 0);
	}

	munmap(shared, sizeof(struct npriv));
OUT:
	free(data);
	pthread_exit(EXIT_SUCCESS);
}

static void *notify_thread(void *data) {
	struct notify *n = data;

	set_thread_name("tsdec-notify");

	while (1) {
		struct npriv *np = queue_get(n->notifications); // Waits...
		if (!np)
			break;
		pthread_t notifier; // The notifier frees the data
		if (pthread_create(&notifier, NULL, &do_notify, np) != 0) {
			perror("pthread_create");
			free(np);
		} else {
			if (np->sync)
				pthread_join(notifier, NULL);
			else
				pthread_detach(notifier);
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

/* ======================================================================== */

struct notify *notify_alloc(struct ts *ts) {
	unsigned int i;
	struct notify *n = calloc(1, sizeof(struct notify));
	if (!n)
		return NULL;

	if (!ts->ident)
		return NULL;

	// Init notify members
	strncpy(n->ident, ts->ident, sizeof(n->ident) - 2);
	for (i=0; i<strlen(n->ident); i++) {
		if (n->ident[i] == '/')
			n->ident[i] = '-';
	}

	// We'll need the notify thread and the queue only if 'notify_program' is set
	if (ts->ident && ts->notify_program) {
		strncpy(n->program, ts->notify_program, sizeof(n->program) - 2);
		n->notifications = queue_new();
		pthread_create(&n->thread, &ts->thread_attr , &notify_thread, n);
	}
	return n;
}

static void npriv_struct_fill(struct npriv *np, struct ts *ts, int sync_msg, char *msg_id, char *msg_text) {
	np->sync = sync_msg;
	if (ts->notify_wait)
		np->sync = 1;
	np->ts = time(NULL);

	strncpy(np->program, ts->notify->program, sizeof(np->program) - 2);
	strncpy(np->ident, ts->notify->ident, sizeof(np->ident) - 2);
	strncpy(np->msg_id, msg_id, sizeof(np->msg_id) - 2);
	strncpy(np->text, msg_text, sizeof(np->text) - 2);

	if (ts->input.type == NET_IO) {
		snprintf(np->input, sizeof(np->input), "%s:%s", ts->input.hostname, ts->input.service);
	} else if (ts->input.type == FILE_IO) {
		snprintf(np->input, sizeof(np->input), "%s", ts->input.fd == 0 ? "STDIN" : "FILE");
	}
	if (ts->output_stream) {
		if (ts->output.type == NET_IO) {
			snprintf(np->output, sizeof(np->output), "%s:%s", ts->output.hostname, ts->output.service);
		} else if (ts->output.type == FILE_IO) {
			snprintf(np->output, sizeof(np->output), "%s", ts->output.fd == 1 ? "STDOUT" : "FILE");
		}
	} else {
		snprintf(np->output, sizeof(np->output), "DISABLED");
	}
}

static void notify_func(struct ts *ts, int sync_msg, char *msg_id, char *msg_text) {
	struct npriv np_local;
	int np_local_inited = 0;

	if (ts->status_file) {
		memset(&np_local, 0, sizeof(np_local));
		npriv_struct_fill(&np_local, ts, sync_msg, msg_id, msg_text);
		np_local_inited = 1;
		// Write status file
		FILE *status_file = fopen(ts->status_file_tmp, "w");
		if (status_file) {
			fprintf(status_file, "%s|%ld|%s|%s|%s|%s\n", np_local.ident, np_local.ts, np_local.msg_id, np_local.text, np_local.input, np_local.output);
			rename(ts->status_file_tmp, ts->status_file);
			fclose(status_file);
		}
	}

	if (ts->notify && ts->notify->notifications) {
		struct npriv *np = calloc(1, sizeof(struct npriv));
		if (np) {
			if (np_local_inited) {
				memcpy(np, &np_local, sizeof(*np));
			} else {
				npriv_struct_fill(np, ts, sync_msg, msg_id, msg_text);
			}
			queue_add(ts->notify->notifications, np);
		}
	}
}

#define MAX_MSG_TEXT 256

void notify(struct ts *ts, char *msg_id, char *text_fmt, ...) {
	va_list args;
	char msg_text[MAX_MSG_TEXT];

	va_start(args, text_fmt);
	vsnprintf(msg_text, sizeof(msg_text) - 1, text_fmt, args);
	msg_text[sizeof(msg_text) - 1] = 0;
	va_end(args);

	notify_func(ts, 0, msg_id, msg_text);
}

void notify_sync(struct ts *ts, char *msg_id, char *text_fmt, ...) {
	va_list args;
	char msg_text[MAX_MSG_TEXT];

	va_start(args, text_fmt);
	vsnprintf(msg_text, sizeof(msg_text) - 1, text_fmt, args);
	msg_text[sizeof(msg_text) - 1] = 0;
	va_end(args);

	notify_func(ts, 1, msg_id, msg_text);
}

void notify_free(struct notify **pn) {
	struct notify *n = *pn;
	if (n) {
		if (n->notifications) {
			queue_add(n->notifications, NULL);
			pthread_join(n->thread, NULL);
			queue_free(&n->notifications);
		}
		FREE(*pn);
	}
}
