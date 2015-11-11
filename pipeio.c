#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <fcntl.h>
#include <md5.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define READSIZE	256
#define WRITESIZE	64
#define BUFSIZE		(READSIZE > WRITESIZE ? READSIZE : WRITESIZE)

void __dead usage(void);
void reader(int);
void writer(int);
void rwio(int, int, size_t, char, char);
void genchar(char *, size_t, char, char, char);

int
main(int argc, char *argv[])
{
	int fd[2], ls, ret = 0;
	pid_t pid[2];
	char *dev;
	struct sockaddr_un sun;

	if (argc != 2)
		usage();

	if (strcmp(argv[1], "socketpair") == 0) {
		if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) == -1)
			err(1, "socketpair");
	}
	if (strcmp(argv[1], "pipe") == 0) {
		if (pipe(fd) == -1)
			err(1, "pipe");
	}
	if (strcmp(argv[1], "fifo") == 0) {
		if (asprintf(&dev, "%s.fifo", getprogname()) == -1)
			err(1, "asprintf");
		unlink(dev);
		if (mkfifo(dev, 0600) == -1)
			err(1, "mkfifo");
	}
	if (strcmp(argv[1], "unix") == 0) {
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
	}

	srandom(5);

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");
	if (fflush(stdout) != 0)
		err(1, "fflush");
	if ((pid[0] = fork()) == -1)
		err(1, "fork");
	if (pid[0] == 0) {
		if (strcmp(argv[1], "fifo") == 0) {
			if ((fd[0] = open(dev, O_RDWR)) == -1)
				err(1, "open");
		} else
			close(fd[1]);
		reader(fd[0]);
		fflush(stdout);
		_exit(0);
	}

	if ((pid[1] = fork()) == -1)
		err(1, "fork");
	if (pid[1] == 0) {
		if (strcmp(argv[1], "fifo") == 0) {
			if ((fd[1] = open(dev, O_RDWR)) == -1)
				err(1, "open");
		} else
			close(fd[0]);
		writer(fd[1]);
		fflush(stdout);
		_exit(0);
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

	return (ret);
}

void __dead 
usage(void)
{
	fprintf(stderr, "%s: socketpair | pipe | fifo | unix\n",
	    getprogname());
	exit(2);
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
	int eof = 0;
	MD5_CTX readctx, writectx;

	MD5Init(&readctx);
	MD5Init(&writectx);

	fds[0].fd = fd;
	fds[0].events = events;

	while ((!writemax && !eof) || (writelen < writemax || !eof)) {
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
			eof = 1;
		}
		if (fds[0].revents & POLLIN) {
			if ((rv = read(fds[0].fd, buf, READSIZE)) == -1)
				err(1, "read");
			if (rv > 0 && buf[rv - 1] == '\0') {
				printf("%d READEOF\n", fds[0].fd);
				eof = 1;
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
				n = random() % WRITESIZE;
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
