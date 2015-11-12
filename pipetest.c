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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <md5.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

#define READSIZE	256
#define WRITESIZE	64
#define BUFSIZE		(READSIZE > WRITESIZE ? READSIZE : WRITESIZE)

void __dead usage(void);
void reader(int);
void writer(int);
void rwio(int, int, size_t, char, char);
void genchar(char *, size_t, char, char, char);
void xchange(int[]);

void __dead
usage(void)
{
	fprintf(stderr, "%s: socketpair | pipe | fifo | unix | pty | ptypair\n",
	    getprogname());
	exit(2);
}

int
main(int argc, char *argv[])
{
	int ch, fd[2], ls, mfd[2], ret = 0;
	pid_t pid[3] = {0, 0, 0};
	const char *mode, *progpath;
	char *dev, ptyname[2][16];
	struct sockaddr_un sun;
	size_t i, j;

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");

	progpath = argv[0];
	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	mode = argv[0];

	if (strcmp(mode, "socketpair") == 0) {
		if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) == -1)
			err(1, "socketpair");
	} else if (strcmp(mode, "pipe") == 0) {
		if (pipe(fd) == -1)
			err(1, "pipe");
	} else if (strcmp(mode, "fifo") == 0) {
		if (asprintf(&dev, "%s.fifo", getprogname()) == -1)
			err(1, "asprintf");
		unlink(dev);
		if (mkfifo(dev, 0600) == -1)
			err(1, "mkfifo");
	} else if (strcmp(mode, "unix") == 0) {
		if (asprintf(&dev, "%s.sock", getprogname()) == -1)
			err(1, "asprintf");
		unlink(dev);
		if ((ls = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
			err(1, "socket");
		memset(&sun, 0, sizeof(sun));
		sun.sun_len = sizeof(sun);
		sun.sun_family = AF_LOCAL;
		if (strlcpy(sun.sun_path, dev, sizeof(sun.sun_path)) >=
		    sizeof(sun.sun_path))
			errx(1, "strlcpy: %s", dev);
		if (bind(ls, (struct sockaddr *)&sun, sizeof(sun)) == -1)
			err(1, "bind");
		if (listen(ls, 1) == -1)
			err(1, "listen");
		if ((fd[1] = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
			err(1, "socket");
		if (connect(fd[1], (struct sockaddr *)&sun, sizeof(sun)) == -1)
			err(1, "connect");
		if ((fd[0] = accept(ls, NULL, 0)) == -1)
			err(1, "accept");
	} else if (strcmp(mode, "pty") == 0) {
		struct termios term;

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

		if (fflush(stdout) != 0)
			err(1, "fflush");
		if ((pid[2] = fork()) == -1)
			err(1, "fork");
		if (pid[2] == 0) {
			close(fd[0]);
			close(fd[1]);
			xchange(mfd);
			fflush(stdout);
			_exit(0);
		}
		close(mfd[0]);
		close(mfd[1]);
	} else if (strcmp(mode, "ptypair") == 0) {
		char *path, *file;
		size_t size;

		size = strlen(progpath) + sizeof("ptypair");
		if ((path = malloc(size)) == NULL)
			err(1, "malloc");
		strlcpy(path, progpath, size);
		if ((file = strrchr(path, '/')) == NULL) {
			strlcpy(path, "ptypair", size);
		} else {
			file++;
			strlcpy(file, "ptypair", size - (file - path));
		}
		
		if (fflush(stdout) != 0)
			err(1, "fflush");
		if ((pid[2] = fork()) == -1)
			err(1, "fork");
		if (pid[2] == 0) {
			execl(path, path, NULL);
			err(1, "exec %s", path);
		}
	} else
		usage();

	if (fflush(stdout) != 0)
		err(1, "fflush");
	for (i = 0, j = 1; i < nitems(fd); i++, j--) {
		if ((pid[i] = fork()) == -1)
			err(1, "fork");
		if (pid[i] == 0) {
			if (strcmp(mode, "fifo") == 0) {
				if ((fd[i] = open(dev, O_RDWR)) == -1)
					err(1, "open");
			} else
				close(fd[j]);
			reader(fd[i]);
			fflush(stdout);
			_exit(0);
		}
	}
	close(fd[0]);
	close(fd[1]);

	while (pid[0] != 0 || pid[1] != 0) {
		int status;
		pid_t wpid;

		if ((wpid = wait(&status)) == -1)
			err(1, "wait");
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0 && ret == 0)
			ret = WEXITSTATUS(status);
		if (WIFSIGNALED(status) && WTERMSIG(status) != 0 && ret == 0)
			ret = WTERMSIG(status);
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			if (wpid == pid[0])
				pid[0] = 0;
			if (wpid == pid[1])
				pid[1] = 0;
		}
	}
	if (strcmp(mode, "pty") == 0)
		kill(pid[2], SIGTERM);

	return (ret);
}

void
reader(int fd)
{
	rwio(fd, POLLIN|POLLOUT, 900, 'A', 'Z');
}

void
writer(int fd)
{
	rwio(fd, POLLIN|POLLOUT, 1000, '0', '9');
}

void
rwio(int fd, int events, size_t writemax, char writebegin, char writeend)
{
	struct pollfd fds[1];
	size_t n = 0, readlen = 0, writelen = 0;
	char out = writebegin, md5str[MD5_DIGEST_STRING_LENGTH];
	MD5_CTX readctx, writectx;

	MD5Init(&readctx);
	MD5Init(&writectx);

	fds[0].fd = fd;
	fds[0].events = events;

	while (fds[0].events & (POLLIN|POLLOUT)) {
		char buf[BUFSIZE + 1];
		ssize_t rv;

		if (poll(fds, 1, INFTIM) == -1)
			err(1, "poll");
		if (fds[0].revents & POLLNVAL)
			errx(1, "POLLNVAL %d", fds[0].fd);
		if (fds[0].revents & POLLERR)
			errx(1, "POLLERR %d", fds[0].fd);
		if (fds[0].revents & POLLHUP) {
			fds[0].events &= ~POLLIN;
		}
		if (fds[0].revents & POLLIN) {
			if ((rv = read(fds[0].fd, buf, READSIZE)) == -1)
				err(1, "read");
			if (rv > 0 && buf[rv - 1] == '\0') {
				printf("%d READEOF\n", fds[0].fd);
				fds[0].events &= ~POLLIN;
				rv--;
			}
			if (rv > 0) {
				buf[rv] = '\0';
				printf("%d >>> %s\n", fds[0].fd, buf);
				readlen += rv;
				MD5Update(&readctx, buf, rv);
			}
		}
		if (fds[0].revents & POLLOUT) {
			if (n == 0)
				n = arc4random() % WRITESIZE;
			if (writemax && n + writelen > writemax)
				n = writemax - writelen;
			if (writemax && writelen == writemax) {
				if (write(fds[0].fd, "", 1) == -1)
					err(1, "write eof");
				printf("%d WRITEEOF\n", fds[0].fd);
				fds[0].events &= ~POLLOUT;
			}
			if (n > 0) {
				genchar(buf, n, out, writebegin, writeend);
				if ((rv = write(fds[0].fd, buf, n)) == -1)
					err(1, "write");
			} else
				rv = 0;
			if (rv > 0) {
				buf[rv] = '\0';
				printf("%d <<< %s\n", fds[0].fd, buf);
				out = buf[rv - 1] + 1;
				writelen += rv;
				n -= rv;
				MD5Update(&writectx, buf, rv);
			}
		}
	}
	printf("%d READLEN: %zu\n", fd, readlen);
	printf("%d READMD5: %s\n", fd, MD5End(&readctx, md5str));
	printf("%d WRITELEN: %zu\n", fd, writelen);
	printf("%d WRITEMD5: %s\n", fd, MD5End(&writectx, md5str));
}

void
genchar(char *buf, size_t n, char c, char begin, char end)
{
	char *p;

	for (p = buf; p < buf + n; p++) {
		if (c > end)
			c = begin;
		*p = c++;
	}
}

void
xchange(int fd[])
{
	struct pollfd fds[2];
	size_t n[2] = {0, 0}, readlen[2] = {0, 0}, writelen[2] = {0, 0};
	char buf[2][BUFSIZE];

	fds[0].fd = fd[0];
	fds[0].events = POLLIN;
	fds[1].fd = fd[1];
	fds[1].events = POLLIN;

	while (fds[0].fd != -1 || fds[1].fd != -1) {
		ssize_t rv;

		if (poll(fds, 2, INFTIM) == -1)
			err(1, "poll");

		if (fds[0].revents & POLLNVAL)
			errx(1, "POLLNVAL %d", fds[0].fd);
		if (fds[1].revents & POLLNVAL)
			errx(1, "POLLNVAL %d", fds[1].fd);
		if (fds[0].revents & POLLERR)
			errx(1, "POLLERR %d", fds[0].fd);
		if (fds[1].revents & POLLERR)
			errx(1, "POLLERR %d", fds[1].fd);

		if (fds[0].revents & POLLHUP)
			fds[0].fd = -1;
		if (fds[1].revents & POLLHUP)
			fds[1].fd = -1;

		if (fds[0].revents & POLLIN) {
			if ((rv = read(fds[0].fd, buf[0], BUFSIZE)) == -1)
				err(1, "read");
			if (rv > 0) {
				readlen[0] += rv;
				n[0] = rv;
				fds[0].events &= ~POLLIN;
				fds[1].events |= POLLOUT;
			}
		}
		if (fds[1].revents & POLLOUT) {
			if ((rv = write(fds[1].fd, buf[0], n[0])) == -1)
				err(1, "write");
			if (rv > 0) {
				writelen[1] += rv;
				n[0] -= rv;
				if (n[0] > 0) {
					memmove(buf[0], buf[0] + rv, n[0]);
				} else {
					fds[0].events |= POLLIN;
					fds[1].events &= ~POLLOUT;
				}
			}
		}

		if (fds[1].revents & POLLIN) {
			if ((rv = read(fds[1].fd, buf[1], BUFSIZE)) == -1)
				err(1, "read");
			if (rv > 0) {
				readlen[1] += rv;
				n[1] = rv;
				fds[1].events &= ~POLLIN;
				fds[0].events |= POLLOUT;
			}
		}
		if (fds[0].revents & POLLOUT) {
			if ((rv = write(fds[0].fd, buf[1], n[1])) == -1)
				err(1, "write");
			if (rv > 0) {
				writelen[0] += rv;
				n[1] -= rv;
				if (n[1] > 0) {
					memmove(buf[1], buf[1] + rv, n[1]);
				} else {
					fds[1].events |= POLLIN;
					fds[0].events &= ~POLLOUT;
				}
			}
		}
	}
	printf("%d READLEN: %zu\n", fd[0], readlen[0]);
	printf("%d WRITELEN: %zu\n", fd[1], writelen[1]);
	printf("%d READLEN: %zu\n", fd[1], readlen[1]);
	printf("%d WRITELEN: %zu\n", fd[0], writelen[0]);
}
