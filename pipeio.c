#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <md5.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define READSIZE	256
#define WRITESIZE	64
#define BUFSIZE		(READSIZE > WRITESIZE ? READSIZE : WRITESIZE)

void reader(int);
void writer(int);
void rwio(int, int, size_t);
void genchar(char *, size_t, char, char, char);

int
main(int argc, char *argv[])
{
	int fd[2], ret = 0;
	pid_t pid[2];

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fd) == -1)
		err(1, "socketpair");

	srandom_deterministic(5);

	if ((pid[0] = fork()) == -1)
		err(1, "fork");
	if (pid[0] == 0) {
		close(fd[1]);
		reader(fd[0]);
		_exit(0);
	}

	if ((pid[1] = fork()) == -1)
		err(1, "fork");
	if (pid[1] == 0) {
		close(fd[0]);
		writer(fd[1]);
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

void
reader(int fd)
{
	rwio(fd, POLLIN|POLLOUT, 900);
}

void
writer(int fd)
{
	rwio(fd, POLLIN|POLLOUT, 1000);
}

void
rwio(int fd, int events, size_t writemax)
{
	struct pollfd fds[1];
	size_t n = 0, readlen = 0, writelen = 0;
	char out = '0', md5str[MD5_DIGEST_STRING_LENGTH];
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
			fds[0].events &= POLLIN;
			eof = 1;
		}
		if (fds[0].revents & POLLIN) {
			if ((rv = read(fds[0].fd, buf, READSIZE)) == -1)
				err(1, "read");
			if (rv > 0 && buf[rv - 1] == '\0') {
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
				fds[0].events &= POLLOUT;
			}
			if (n > 0) {
				genchar(buf, n, out, '0', '9');
				if ((rv = write(fds[0].fd, buf, n)) == -1)
					err(1, "write");
			} else
				rv = 0;
			if (rv > 0) {
				buf[rv] = '\0';
				printf("%d <<< %s\n", fds[0].fd, buf);
				out = ((out+rv-'0') % (1+'9'-'0')) + '0';
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
		*p = c;
		if (c++ >= end)
			c = begin;
	}
}
