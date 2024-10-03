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

void
usage(void)
{
	fprintf(stderr, "USAGE: %s [-d] [-k file] [-o output] [file]\n", argv0);
	exit(0);
}

#define ntohl(x) htonl(x)
#define htonll(x) ntohll(x)
#define MIN(x, y) ((x) > (y) ? (y) : (x))

uint64_t
ntohll(uint64_t x)
{
	union {
		unsigned int i;
		char c[4];
	} u = {0x00000001};

	uint32_t *p = (uint32_t *) &x;
	uint32_t y;

	if (u.c[0]) {
		// Little-endian system
		y = p[0];
		p[0] = ntohl(p[1]);
		p[1] = ntohl(y);
	}

	return x;
}

int
main(int argc, char **argv)
{
	int fd = -1, kfd = -1, ofd = -1;
	uint64_t len = 0;
	unsigned char key[56];
	ssize_t keylen = 0;
	ssize_t iosz;
	uint32_t x[2], y[2];
	char *kfile = "-", *ofile = NULL;
	int decipher = 0;

	ARGBEGIN {
	case 'd':
		enc = bf_decipher;
		decipher = 1;
		break;
	case 'k':
		kfile = EARGF(usage());
		break;
	case 'o':
		ofile = EARGF(usage());
		break;
	} ARGEND;

	if (argc == 0) {
		fprintf(stderr, "Error: no input files.");
		return 1;
	}
/*
	if (ofile) {
		if (!strcmp(ofile, "-")) {
			// Set output to stdout
			ofd = 1;
		} else {
			ofd = open(ofile, O_WRONLY);
			if (ofd < 0) {
				perror(ofile);
				return 2;
			}
		}
	}
*/
	if (!strcmp(kfile, "-")) {
		// Key is given by stdin
		kfd = 0;
	} else {
		kfd = open(kfile, O_RDONLY);
		if (kfd < 0) {
			perror(kfile);
			return 3;
		}
	}

	memset(key, 0, sizeof key);
	keylen = read(kfd, key, sizeof key);
	close(kfd);

	if (keylen < 0) {
		perror("read");
		// Just in case
		memset(key, 0, sizeof key);
		return 4;
	}
	// This should work for even 0-length keys
	bf_init(key, keylen);
	// The key is no longer needed. Clear it
	memset(key, 0, sizeof key);

	// Iterate over input files
	while (argc > 0) {
		fd = open(argv[0], O_RDWR);

		if (fd < 0) {
			perror(argv[0]);
			// Try next file
			argc--;
			argv++;
			continue;
		}

		if (decipher) {
			// Read file length
			if (read(fd, &len, 8) < 8) {
				perror(argv[0]);
				close(fd);
				continue;
			}
			// Convert to host endianess
			len = ntohll(len);

			if (len == 0) {
				close(fd);
				continue;
			}
			memset(x, 0, sizeof x);
			while ((iosz = read(fd, x, sizeof x) > 0)) {
				x[0] = ntohl(x[0]);
				x[1] = ntohl(x[1]);
				bf_decipher(x, x + 1);
				// Jump back to write cipher data
				lseek(fd, -16, SEEK_CUR);
				write(fd, x, 8);
				// Jump back to next position
				lseek(fd, 8, SEEK_CUR);
				memset(x, 0, sizeof x);
			}

			ftruncate(fd, len);
		} else {
			len = (uint64_t) lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);
			read(fd, x, sizeof x);
			lseek(fd, 0, SEEK_SET);
			len = htonll(len);
			write(fd, &len, sizeof len);

			while ((iosz = read(fd, y, sizeof y)) >= 0) {
				if (iosz == 0) {
					// Write last block
					bf_encipher(x, x + 1);
					x[0] = htonl(x[0]);
					x[1] = htonl(x[1]);
					write(fd, x, sizeof x);
					break;
				}

				lseek(fd, -iosz, SEEK_CUR);
				bf_encipher(x, x + 1);
				x[0] = htonl(x[0]);
				x[1] = htonl(x[1]);
				write(fd, x, sizeof x);
				memcpy(x, y, sizeof x);
			}
		}

		close(fd);
		argc--;
		argv++;
	}

	bf_done();

	return 0;
}

