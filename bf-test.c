#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bf.h"
#include "bf-test.h"

int
main(int argc, char **argv)
{
	int i;
	uint32_t l, r;
	int len = 1;
	int passed = 0;

	for (i = 0; i < NUM_VARIABLE_KEY_TESTS; i++) {
		bf_init(variable_key[i], 8);
		l = plaintext_l[i];
		r = plaintext_r[i];
		printf("%.8X %.8X | ", l, r);
		bf_encipher(&l, &r);
		printf("%.8X %.8X | %.8X %.8X | ",
		  l, r, (uint32_t)ciphertext_l[i],
		  (uint32_t)ciphertext_r[i]);
		if (l == ciphertext_l[i] && r == ciphertext_r[i]) {
			passed++;
			puts("*PASSED*");
		} else
			puts("-FAILED");
	}

	puts("Set tests.");
	for (i = NUM_VARIABLE_KEY_TESTS;
	  i < NUM_VARIABLE_KEY_TESTS + NUM_SET_KEY_TESTS; i++) {
		bf_init(set_key, len++);
		l = plaintext_l[i];
		r = plaintext_r[i];
		printf("%.8X %.8X | ", l, r);
		bf_encipher(&l, &r);
		printf("%.8X %.8X | %.8X %.8X | ",
		  l, r, (int)ciphertext_l[i],
		  (int)ciphertext_r[i]);
		if (l == ciphertext_l[i] && r == ciphertext_r[i]) {
			passed++;
		puts("*PASSED*");
		} else
			puts("-FAILED");
	}

	printf("%d tests passed out of %d.\n", passed, NUM_VARIABLE_KEY_TESTS +
	  NUM_SET_KEY_TESTS);
	return 0;
}

