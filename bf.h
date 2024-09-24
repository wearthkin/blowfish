#ifndef __BF_H__
#define __BF_H__

void bf_encipher(uint32_t *, uint32_t *);
void bf_decipher(uint32_t *, uint32_t *);
void bf_init(unsigned char *, size_t);
void bf_done(void);

#endif

