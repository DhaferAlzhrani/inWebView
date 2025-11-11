#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "helper.h"
#include "aes.h"
#include "utils.h"
#include <time.h>

// #include <arm_neon.h>   // vaeseq_u8, vaesmcq_u8, veorq_u8, uint8x16_t
/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

struct AES_ctx ctx;

static void inc32(u8 *block)
{
	u32 val;
	val = WPA_GET_BE32(block + AES_BLOCK_SIZE - 4);
	val++;
	WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}

static void xor_block(u8 *dst, const u8 *src)
{
	for (int i = 0; i < 16; i++)
		dst[i] ^= src[i];
}

static void shift_right_block(u8 *v)
{
	u32 val;
	val = WPA_GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 12, val);
	val = WPA_GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 8, val);
	val = WPA_GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 4, val);
	val = WPA_GET_BE32(v);
	val >>= 1;
	WPA_PUT_BE32(v, val);
}
/* Multiplication in GF(2^128) */
static void gf_mult(const u8 *x, const u8 *y, u8 *z)
{
	u8 v[16];
	int i, j;
	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */
	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < 8; j++)
		{
			if (x[i] & BIT(7 - j))
			{
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			}
			else
			{
				/* Z_(i + 1) = Z_i */
			}
			if (v[15] & 0x01)
			{
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			}
			else
			{
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}
static void ghash_start(u8 *y)
{
	/* Y_0 = 0^128 */
	memset(y, 0, 16);
}
static void ghash(const u8 *h, const u8 *x, size_t xlen, u8 *y)
{
	if (xlen == 0)
		return; // ← الأمان من NULL + 0
	size_t m, i;
	const u8 *xpos = x;
	u8 tmp[16];
	m = xlen / 16;
	for (i = 0; i < m; i++)
	{
		xor_block(y, xpos);
		xpos += 16;
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}
	if (x + xlen > xpos)
	{
		size_t last = (size_t)((x + xlen) - xpos);
		memcpy(tmp, xpos, last);
		memset(tmp + last, 0, sizeof(tmp) - last);
		xor_block(y, tmp);
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}
}

static void aes_gctr(struct AES_ctx *ctx_aes, const u8 *icb, const u8 *x, size_t xlen, u8 *y)
{
	size_t i, n, last;
	u8 cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const u8 *xpos = x;
	u8 *ypos = y;
	if (xlen == 0)
		return;
	n = xlen / 16;
	memcpy(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++)
	{
		AES_ECB_encrypt(ctx_aes, cb, ypos);
		xor_block(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		inc32(cb);
	}
	last = x + xlen - xpos;
	if (last)
	{
		/* Last, partial block */
		AES_ECB_encrypt(ctx_aes, cb, tmp);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}
static void aes_gcm_init_hash_subkey(const u8 *key, size_t key_len, u8 *H)
{

	AES_init_ctx(&ctx, key);
	u8 tmp[AES_BLOCK_SIZE] = {0};
	memset(H, 0, AES_BLOCK_SIZE);
	AES_ECB_encrypt(&ctx, H, tmp);
	memcpy(H, tmp, AES_BLOCK_SIZE);
}
static void aes_gcm_prepare_j0(const u8 *iv, size_t iv_len, const u8 *H, u8 *J0)
{
	u8 len_buf[16];
	if (iv_len == 12)
	{
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, AES_BLOCK_SIZE - iv_len);
		J0[AES_BLOCK_SIZE - 1] = 0x01;
	}
	else
	{
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		ghash_start(J0);
		ghash(H, iv, iv_len, J0);
		WPA_PUT_BE64(len_buf, 0);
		WPA_PUT_BE64(len_buf + 8, iv_len * 8);
		ghash(H, len_buf, sizeof(len_buf), J0);
	}
}
static void aes_gcm_gctr(struct AES_ctx *ctx_aes, const u8 *J0, const u8 *in, size_t len,
						 u8 *out)
{
	u8 J0inc[AES_BLOCK_SIZE];
	if (len == 0)
		return;
	memcpy(J0inc, J0, AES_BLOCK_SIZE);
	inc32(J0inc);
	aes_gctr(ctx_aes, J0inc, in, len, out);
}
static void aes_gcm_ghash(const u8 *H, const u8 *aad, size_t aad_len,
						  const u8 *crypt, size_t crypt_len, u8 *S)
{
	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	u8 len_buf[16];
	ghash_start(S);
	if (aad_len)
		ghash(H, aad, aad_len, S);
	if (crypt_len)
		ghash(H, crypt, crypt_len, S);
	WPA_PUT_BE64(len_buf, (u64)aad_len * 8);
	WPA_PUT_BE64(len_buf + 8, (u64)crypt_len * 8);
	ghash(H, len_buf, sizeof(len_buf), S);
}
/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
int aes_gcm_ae(const u8 *key, size_t key_len, const u8 *iv, size_t iv_len,
			   const u8 *plain, size_t plain_len,
			   const u8 *aad, size_t aad_len, u8 *crypt, u8 *tag)
{
	u8 H[AES_BLOCK_SIZE];
	u8 J0[AES_BLOCK_SIZE];
	u8 S[16];
	aes_gcm_init_hash_subkey(key, key_len, H);

	aes_gcm_prepare_j0(iv, iv_len, H, J0);
	/* C = GCTR_K(inc_32(J_0), P) */
	aes_gcm_gctr(&ctx, J0, plain, plain_len, crypt);
	aes_gcm_ghash(H, aad, aad_len, crypt, plain_len, S);
	/* T = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(&ctx, J0, S, sizeof(S), tag);
	/* Return (C, T) */
	return 0;
}
/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */

__attribute__((visibility("default")))
int aes_gcm_ad(const u8 *key, size_t key_len, const u8 *iv, size_t iv_len,
			   const u8 *crypt, size_t crypt_len,
			   const u8 *aad, size_t aad_len, const u8 *tag, u8 *plain)
{
	u8 H[AES_BLOCK_SIZE];
	u8 J0[AES_BLOCK_SIZE];
	u8 S[16], T[16];
	aes_gcm_init_hash_subkey(key, key_len, H);

	aes_gcm_prepare_j0(iv, iv_len, H, J0);
	/* P = GCTR_K(inc_32(J_0), C) */
	aes_gcm_gctr(&ctx, J0, crypt, crypt_len, plain);
	aes_gcm_ghash(H, aad, aad_len, crypt, crypt_len, S);
	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(&ctx, J0, S, sizeof(S), T);
	if (memcmp(tag, T, 16) != 0)
	{
		printf("GCM: Tag mismatch");
		return -1;
	}
	return 0;
}
int aes_gmac(const u8 *key, size_t key_len, const u8 *iv, size_t iv_len,
			 const u8 *aad, size_t aad_len, u8 *tag)
{
	return aes_gcm_ae(key, key_len, iv, iv_len, NULL, 0, aad, aad_len, NULL,
					  tag);
}

// // rk[0..14]: 15 round keys of 16 bytes (AES-256)

// __attribute__((visibility("default")))

// void aes256_encrypt_block_arm(uint8_t out[16],
//                                             const uint8_t in[16],
//                                             const uint8_t rk[15][16]) {
//     uint8x16_t block = vld1q_u8(in);

//     block = vaeseq_u8(block, vld1q_u8(rk[0]));
//     block = vaesmcq_u8(block);

//     for (int i = 1; i < 14 - 1; i += 2)
//     {
//         block = vaeseq_u8(block, vld1q_u8(rk[i]));
//         block = vaesmcq_u8(block);
//         block = vaeseq_u8(block, vld1q_u8(rk[i+1]));
//         block = vaesmcq_u8(block);
//     }

//     block = vaeseq_u8(block, vld1q_u8(rk[13]));
//     block = veorq_u8(block, vld1q_u8(rk[14]));

//     vst1q_u8(out, block);
// }

// int main(void) {
//     // Test input: 16-byte plaintext
//     uint8_t plaintext[16] = {
//         0x00, 0x11, 0x22, 0x33,
//         0x44, 0x55, 0x66, 0x77,
//         0x88, 0x99, 0xaa, 0xbb,
//         0xcc, 0xdd, 0xee, 0xff
//     };

//     // Dummy key schedule (for real use, run AES-256 key expansion)
//     uint8_t round_keys[15][16];
//     for (int i = 0; i < 15; i++) {
//         for (int j = 0; j < 16; j++) {
//             round_keys[i][j] = (uint8_t)(i * 16 + j);
//         }
//     }

//     uint8_t ciphertext[16];
//     aes256_encrypt_block_arm(ciphertext, plaintext, round_keys);

//     printf("Ciphertext:\n");
//     for (int i = 0; i < 16; i++) {
//         printf("%02x ", ciphertext[i]);
//     }
//     printf("\n");

//     return 0;
// }

void main()
{

	clock_t start_time, end_time;
	double cpu_time_used;

	start_time = clock(); // Record the start time

	uint8_t out[64];
	uint8_t tag[64];
	uint8_t key[32] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	// uint8_t key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
	int8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	// uint8_t msg[64] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};
	uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

	aes_gcm_ae(key, 32, iv, 16, msg, 13, NULL, 0, out, tag);

	end_time = clock(); // Record the end time

	cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds

	printf("aes_gcm_ae execution time: %f ms\n", cpu_time_used * 1000);

	DumpHex(out, 64);
	DumpHex(tag, 16);
}