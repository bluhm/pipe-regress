/*
 * Copyright (c) 2015 Alexander Bluhm <bluhm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/ioctl.h>
#include <sys/param.h>

#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
#include <vis.h>

#define BUFSIZE		4096

void __dead usage(void);

void __dead
usage(void)
{
	fprintf(stderr, "%s\n", getprogname());
	exit(2);
}

int
main(int argc, char *argv[])
{
	char ptyname[2][16], buf[2][BUFSIZE], str[4 * BUFSIZE + 1];
	size_t n[2] = {0, 0}, readlen[2] = {0, 0}, writelen[2] = {0, 0}, i, j;
	struct pollfd fds[3];
	struct termios term;
	int ch, fd[2], mfd[2];

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	ch = 1;
	memset(&term, 0, sizeof(term));
	cfmakeraw(&term);
	for (i = 0; i < nitems(mfd); i++) {
		if (openpty(&mfd[i], &fd[i], ptyname[i], &term, NULL) == -1)
			err(1, "openpty");
		if (ioctl(mfd[i], TIOCEXT, &ch) == -1)
			err(1, "ioctl TIOCEXT");
		if (ioctl(mfd[i], TIOCREMOTE, &ch) == -1)
			err(1, "ioctl TIOCREMOTE");
	}

	fds[0].fd = mfd[0];
	fds[0].events = POLLIN;
	fds[1].fd = mfd[1];
	fds[1].events = POLLIN;
	fds[2].fd = STDIN_FILENO;
	fds[2].events = POLLIN;

	/* finish if both ends have finished or stdin has been closed */
	while ((fds[0].fd != -1 || fds[1].fd != -1) && fds[2].fd != -1) {
		ssize_t rv;

		if (poll(fds, nitems(fds), INFTIM) == -1)
			err(1, "poll");

		/* exit on error, detect hangup */
		for (i = 0; i < nitems(fds); i++) {
			if (fds[i].revents & POLLNVAL)
				errx(1, "POLLNVAL %d", fds[i].fd);
			if (fds[i].revents & POLLERR)
				errx(1, "POLLERR %d", fds[i].fd);
			if (fds[i].revents & POLLHUP)
				fds[i].fd = -1;
		}

		/* copy bidirectional between master pseudo terminals */
		for (i = 0, j = 1; i < nitems(mfd); i++, j--) {
			if (fds[i].revents & POLLIN) {
				if ((rv = read(fds[i].fd, buf[i], BUFSIZE))
				    == -1)
					err(1, "read %d", fds[i].fd);
				if (rv > 0) {
					strvisx(str, buf[i], rv, VIS_NL);
					printf("%d >>> %s\n", fds[i].fd, str);
					readlen[i] += rv;
					n[i] = rv;
					fds[i].events &= ~POLLIN;
					fds[j].events |= POLLOUT;
				} else
					printf("%d >>> EOF", fds[i].fd);
			}
			if (fds[j].revents & POLLOUT) {
				if ((rv = write(fds[j].fd, buf[i], n[i])) == -1)
					err(1, "write");
				if (rv > 0) {
					strvisx(str, buf[i], rv, VIS_NL);
					printf("%d <<< %s\n", fds[j].fd, str);
					writelen[j] += rv;
					n[i] -= rv;
					if (n[i] > 0) {
						memmove(buf[i], buf[i] + rv,
						    n[i]);
					} else {
						fds[i].events |= POLLIN;
						fds[j].events &= ~POLLOUT;
					}
				} else
					printf("%d <<< EOF", fds[j].fd);
			}
		}

		/* discard everything from stdin */
		if (fds[2].revents & POLLIN) {
			if (read(fds[2].fd, str, BUFSIZE) == -1)
				err(1, "read stdin");
		}
	}

	/* log statistics */
	for (i = 0, j = 1; i < nitems(mfd); i++, j--) {
		printf("%d READLEN: %zu\n", fd[i], readlen[i]);
		printf("%d WRITELEN: %zu\n", fd[i], writelen[i]);
	}

	return (0);
}
