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
	fprintf(stderr, "USAGE: %s [-d] [-k file] [-o output] [file]\n", argv0);
	exit(0);
}

#define ntohl(x) htonl(x)
#define ntohll(x) htonll(x)

int
readw(int fd, uint32_t *x)
{
	int r;
	uint32_t t;
	r = read(fd, x, 8);
	t = x[0];
	x[0] = ntohl(x[1]);
	x[1] = ntohl(t);
	return r;
}

void
readws(unsigned char *buff, uint32_t *x)
{
	uint32_t *p = (uint32_t *) buff;
	uint32_t t;
	t = x[0];
	x[0] = ntohl(p[1]);
	x[1] = ntohl(t);
}

int
writew(int fd, uint32_t *x, size_t len)
{
	uint32_t t;
	int r;
	t = x[0];
	x[0] = htonl(x[1]);
	x[1] = htonl(t);
	r = write(fd, x, len);
	t = x[0];
	x[0] = ntohl(x[1]);
	x[1] = ntohl(t);
	return r;
}

int
main(int argc, char **argv)
{
	int decipher = 0;
	int kfd = -1;
	int fd = 0;
	int ofd = 1;
	unsigned char key[56];
	char *kfile = NULL;
	char *ofile = NULL;
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
		kfile = EARGF(usage());
		break;
	case 'o':
		ofile = EARGF(usage());
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
	} else if (argc > 1)
		usage();

	if (fd == 0) {
		// Ensure the key is not also set as stdin
		if (kfile != NULL && !strcmp(kfile, "-")) {
			fprintf(stderr, "Key and input both stdin. Exiting.\n");
			usage();
		}

		inlen = BUFFSZ;
		in = malloc(inlen);
		len = 0;
		memset(in, 0, inlen);

		if (!in) {
			fprintf(stderr, "memory\n");
			return 1;
		}

		while ((rd = read(fd, buff, BUFFSZ)) > 0) {
			if (rd < 0) {
				perror("read");
				return 1;
			}

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
		// This will ensure zero padding if input length is not a
		// multiple 8-bytes
		inlen = ((inlen + 7) / 8) * 8;
		in = malloc(inlen);

		if (!in) {
			fprintf(stderr, "Memory fail.\n");
			return 1;
		}

		// zero-padding
		memset(in, 0, inlen);
		if (read(fd, in, inlen) < 0) {
			perror("read");
			free(in);
			return 1;
		}
	}

	if (kfile != NULL) {
		if (!strcmp(kfile, "-"))
			kfd = 0;
		else
			kfd = open(kfile, O_RDONLY);

		if (kfd < 0) {
			perror("failed to open key file\n");
			return 1;
		}

	}

	if (kfd >= 0) {
		keylen = read(kfd, key, sizeof key);

		if (keylen < 0) {
			perror("read");
			free(in);
			memset(key, 0, sizeof key);
			return 1;
		}

		close(kfd);
		kfd = -1;
	}

	if (ofile != NULL) {
		ofd = open(ofile, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (ofd < 0) {
			perror("failed to open output file\n");
			free(in);
			memset(key, 0, sizeof key);
			return 1;
		}
	}

	bf_init(key, keylen);
	memset(key, 0, sizeof key);
	keylen = 0;

	if (decipher) {
		// Start by reading the file length (first 8 bytes)
		if (fd == 0) {
			readws(in, (uint32_t *) &sz);
			in += 8;
		} else {
			lseek(fd, 0, SEEK_SET);
			readw(fd, (uint32_t *) &sz);
			in += 8;
		}
		// This is accounts for the file length (first 8 bytes)
		inlen -= 8;

		for (uint32_t i = 0; i < inlen; i+= 8) {
			memcpy(x, in + i, 8);
			x[0] = ntohl(x[0]);
			x[1] = ntohl(x[1]);
			bf_decipher(x, x + 1);
			// Ensure no more than `sz' bytes are written
			if (i + 8 > sz)
				rd = write(ofd, x, sz - i);
			else
				rd = write(ofd, x, 8);
		}

		ftruncate(ofd, sz);
	} else {
		// Start by writing out the file length
		writew(ofd, (uint32_t *) &len, 8);
		for (uint32_t i = 0; i < len; i += 8) {
			memcpy(x, in + i, 8);
			bf_encipher(x, x + 1);
			x[0] = htonl(x[0]);
			x[1] = htonl(x[1]);
			write(ofd, x, 8);
		}
	}

	close(ofd);

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

