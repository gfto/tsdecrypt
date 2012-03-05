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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
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
	char	ident[512];
	char	program[512];
	char	msg_id[512];
	char	text[512];
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
		asprintf(&env[e++], "_TS=%ld"			, time(NULL));
		asprintf(&env[e++], "_IDENT=%s"			, shared->ident);
		asprintf(&env[e++], "_MESSAGE_ID=%s"	, shared->msg_id);
		asprintf(&env[e++], "_MESSAGE_TEXT=%s"	, shared->text);
		r = strlen(shared->msg_id);
		for (i=0; i<r; i++) {
			if (isalpha(shared->msg_id[i]))
				shared->msg_id[i] = tolower(shared->msg_id[i]);
			if (shared->msg_id[i] == '_')
				shared->msg_id[i] = ' ';
		}
		asprintf(&env[e++], "_MESSAGE_MSG=%s"	, shared->msg_id);
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
	if (!ts->ident || !ts->notify_program)
		return NULL;
	struct notify *n = calloc(1, sizeof(struct notify));
	n->notifications = queue_new();
	strncpy(n->ident, ts->ident, sizeof(n->ident) - 1);
	n->ident[sizeof(n->ident) - 1] = '\0';
	for (i=0; i<strlen(n->ident); i++) {
		if (n->ident[i] == '/')
			n->ident[i] = '-';
	}
	strncpy(n->program, ts->notify_program, sizeof(n->program) - 1);
	n->program[sizeof(n->program) - 1] = '\0';
	pthread_create(&n->thread, NULL , &notify_thread, n);
	return n;
}

static void npriv_init_defaults(struct notify *n, struct npriv *np) {
	strncpy(np->program, n->program, sizeof(np->program) - 1);
	strncpy(np->ident, n->ident, sizeof(np->ident) - 1);
}

static void notify_func(struct ts *ts, int sync_msg, char *msg_id, char *msg_text) {
	struct npriv *np;

	if (!ts->notify)
		return;

	np = calloc(1, sizeof(struct npriv));

	np->sync = sync_msg;
	npriv_init_defaults(ts->notify, np);

	strncpy(np->msg_id, msg_id, sizeof(np->ident) - 1);
	np->msg_id[sizeof(np->ident) - 1] = 0;

	strncpy(np->text, msg_text, sizeof(np->text) - 1);
	np->text[sizeof(np->text) - 1] = 0;

	queue_add(ts->notify->notifications, np);
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
		queue_add(n->notifications, NULL);
		pthread_join(n->thread, NULL);
		queue_free(&n->notifications);
		FREE(*pn);
	}
}
