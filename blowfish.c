#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "arg.h"
#include "bf.h"

#define BUFFSZ 8192
char *argv0 = NULL;
ssize_t inlen = 0;
unsigned char *in = NULL;

void
usage(void)
{
	fprintf(stderr, "USAGE: %s [-d] [-k file] [file]\n", argv0);
	exit(0);
}

#define ntohl(x) htonl(x)
#define ntohll(x) htonll(x)

int
readw(int fd, uint32_t *x)
{
	int r;
	r = read(fd, x, 8);
	x[0] = ntohl(x[0]);
	x[1] = ntohl(x[1]);
	return r;
}

void
readws(unsigned char *buff, uint32_t *x)
{
	uint32_t *p = (uint32_t *) buff;
	x[0] = ntohl(p[0]);
	x[1] = ntohl(p[1]);
}

int
writew(int fd, uint32_t *x, size_t len)
{
	int r;
	x[0] = htonl(x[0]);
	x[1] = htonl(x[1]);
	r = write(fd, x, len);
	x[0] = ntohl(x[0]);
	x[1] = ntohl(x[1]);
	return r;
}

void
encipher()
{
}

int
main(int argc, char **argv)
{
	int decipher = 0;
	int kfd = -1;
	int fd = 0;
	int ofd = 1;
	unsigned char key[56];
	char *a = NULL;
	size_t keylen = 0;
	char buff[BUFFSZ];
	ssize_t rd;
	ssize_t len = 0;
	uint32_t x[2];
	uint64_t sz;

	argv0 = argv[0];
	memset(key, 0, sizeof key);

	ARGBEGIN {
	case 'd':
		decipher = 1;
		break;
	case 'k':
		a = EARGF(usage());
		if (!strcmp(a, "-"))
			kfd = 0;
		else {
			kfd = open(a, O_RDONLY);
			if (kfd < 0) {
				perror(a);
				return 1;
			}
		}
		break;
	case 'o':
		a = EARGF(usage());
		ofd = open(a, O_WRONLY);
		if (ofd < 0) {
			fprintf(stderr, "Failed to open file for writing.");
			return 1;
		}
		break;
	default:
		usage();
	} ARGEND;

	if (argc == 1) {
		fd = open(argv[0], O_RDONLY);
		if (fd < 0) {
			perror(argv[0]);
			return 1;
		}
	} else if (argc > 1 && kfd != -1)
		usage();


	if (fd == 0) {
		inlen = BUFFSZ;
		in = malloc(inlen);
		len = 0;
		memset(in, 0, inlen);

		if (!in) {
			fprintf(stderr, "memory\n");
			return 1;
		}

		while ((rd = read(fd, buff, BUFFSZ)) > 0) {
			if (len + rd > inlen) {
				inlen *= 2;
				in = realloc(in, inlen);

				if (!in) {
					fprintf(stderr, "memory fail.\n");
					return 1;
				}
			}

			memcpy(in + len, buff, rd);
			len += rd;
		}
	} else {
		inlen = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		len = inlen;
		inlen = ((inlen + 7) / 8) * 8;
		in = malloc(inlen);
		if (!in) {
			fprintf(stderr, "Memory fail.\n");
			return 1;
		}

		memset(in, 0, inlen);
		read(fd, in, inlen);
	}

	if (kfd == fd)
		usage();

	if (kfd == -1) {
		keylen=56;
		memset(key, 0, sizeof key);
	} else {
		keylen = read(kfd, key, sizeof key);
	}

	bf_init(key, keylen);
	memset(key, 0, sizeof key);
	keylen = 0;

	if (decipher) {
		if (fd == 0) {
			readws(in, (uint32_t *) &sz);
			in += 8;
		} else {
			lseek(fd, 0, SEEK_SET);
			readw(fd, (uint32_t *) &sz);
			in = in + 8;
		}

		inlen -= 8;

		for (uint32_t i = 0; i < inlen; i+= 8) {
			memcpy(x, in + i, 8);
			bf_decipher(x, x + 1);
			if (i + 8 > sz)
				write(ofd, x, sz - i);
			else
				write(ofd, x, 8);
		}

		ftruncate(ofd, sz);
	} else {
		writew(ofd, (uint32_t *) &len, 8);
		for (uint32_t i = 0; i < len; i+= 8) {
			memcpy(x, in + i, 8);
			bf_encipher(x, x + 1);
			write(ofd, x, 8);
		}
	}

	if (in) {
		if (decipher) {
			/*
			 * in decipher mode these are altered to skip
			 * the file length at the beginning of input
			 */
			inlen += 8;
			in -= 8;
		}

		memset(in, 0, inlen);
		free(in);
	}

	bf_done();

	return 0;
}

