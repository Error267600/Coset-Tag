/* SPDX-License-Identifier: MIT OR GPL-2.0
 * Copyright (c) 2026 — Coset Authentication Tag
 * Lattice-based private-verifiable message authentication for KEMs */

#ifndef COSET_TAG_H
#define COSET_TAG_H

#include <stdint.h>
#include <stddef.h>

#define COSET_TAG_N         256
#define COSET_TAG_K         2
#define COSET_TAG_Q         3329
#define COSET_TAG_B_D       4
#define COSET_TAG_DOMAIN    "coset_tag_v1"
#define COSET_TAG_COEFFS    (COSET_TAG_K * COSET_TAG_N)
#define COSET_TAG_BYTES     (COSET_TAG_COEFFS * 12 / 8)

typedef struct coset_tag_ctx coset_tag_ctx;


coset_tag_ctx *coset_tag_create(int (*entropy_fn)(void *buf, size_t len));

void coset_tag_destroy(coset_tag_ctx *ctx);


int coset_tag_generate(const coset_tag_ctx *ctx,
                       const uint8_t *u_bytes, size_t u_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t *z_out, size_t z_out_len);

int coset_tag_verify(const coset_tag_ctx *ctx,
                     const uint16_t *true_u, size_t u_coeffs,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *z_bytes, size_t z_len);


void coset_tag_pack(const int16_t *coeffs, size_t n, uint8_t *out);

void coset_tag_unpack(const uint8_t *in, size_t byte_len, int16_t *coeffs, size_t n);


int coset_tag_get_d(const coset_tag_ctx *ctx, int16_t *d_out, size_t d_coeffs);

#endif
