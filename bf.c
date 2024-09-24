#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bf-data.h"

static uint32_t P[18];
static uint32_t S[4][256];

static uint32_t F(uint32_t x)
{
	uint32_t h = S[0][x >> 24] + S[1][(x >> 16) & 0xff];
	return (h ^ S[2][(x >> 8) & 0xff]) + S[3][x & 0xff];
}

void bf_encipher(uint32_t *L, uint32_t *R)
{
	int i;
	uint32_t l = *L, r = *R;

	for (i = 0; i < 16; i += 2) {
		l ^= P[i];
		r ^= F(l);
		r ^= P[i+1];
		l ^= F(r);
	}

	l ^= P[16];
	r ^= P[17];
	*L = r;
	*R = l;
	l = 0;
	r = 0;
}

void bf_decipher(uint32_t *L, uint32_t *R)
{
	int i;
	uint32_t l = *L, r = *R;

	for (i = 16; i > 0; i -= 2) {
		l ^= P[i + 1];
		r ^= F(l);
		r ^= P[i];
		l ^= F(r);
	}

	l ^= P[1];
	r ^= P[0];
	*L = r;
	*R = l;
	l = 0;
	r = 0;
}

void bf_init(unsigned char *key, size_t keylen)
{
	unsigned int i, j;
	uint32_t l, r, t, k;

	memcpy(P, parray, sizeof P);
	memcpy(S, sbox, sizeof S);
	j = 0;

	for (i = 0; i < 18; i++) {
		t = 0;
		for (k = 0; k < 4; k++) {
			t = (t << 8) | key[j];
			if (++j >= keylen)
				j = 0;
		}
		P[i] ^= t;
	}

	l = 0;
	r = 0;
	t = 0;

	for (i = 0; i < 18; i += 2) {
		bf_encipher(&l, &r);
		P[i] = l;
		P[i+1] = r;
	}

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j += 2) {
			bf_encipher(&l, &r);
			S[i][j] = l;
			S[i][j + 1] = r;
		}
	}

	l = 0;
	r = 0;
}

void bf_done(void)
{
	memset(P, 0, sizeof P);
	memset(S, 0, sizeof S);
}

