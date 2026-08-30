// Copyright (c) 2026 Hello
// Self-contained: embeds Keccak, SHAKE256, NTT
// SPDX-License-Identifier: MIT OR GPL-2.0
//
// Copyright (c) 2026 kstzv — Original ML-KEM implementation
// Source: https://github.com/kstzv/ml-kem
// Licensed under MIT OR GPL-2.0
//
// This file embeds ML-KEM primitives (Keccak-f[1600], SHAKE256, NTT,
// key generation, encapsulation, decapsulation) from the above project.






typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;


STATIC inline u16 add_mod(u16 a, u16 b) {
    u16 c = a + b; return c >= Q ? c - Q : c;
}
STATIC inline u16 sub_mod(u16 a, u16 b) {
    return a >= b ? a - b : a + Q - b;
}
STATIC inline u16 mul_mod(u16 a, u16 b) {
    return (u16)(((u32)a * b) % Q);
}
STATIC inline int16_t to_signed(u16 x) {
    return (x > Q / 2) ? (int16_t)(x - Q) : (int16_t)x;
}
STATIC inline u16 to_unsigned(int16_t x) {
    return (u16)((x + Q) % Q);
}



STATIC const u64 keccakf_rndc[KECCAKF_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

STATIC void keccak_f1600(u64 state[25]) {
    u64 Aba,Abe,Abi,Abo,Abu,Aga,Age,Agi,Ago,Agu;
    u64 Aka,Ake,Aki,Ako,Aku,Ama,Ame,Ami,Amo,Amu;
    u64 Asa,Ase,Asi,Aso,Asu;
    u64 BCa,BCe,BCi,BCo,BCu,Da,De,Di,Do,Du;
    u64 Eba,Ebe,Ebi,Ebo,Ebu,Ega,Ege,Egi,Ego,Egu;
    u64 Eka,Eke,Eki,Eko,Eku,Ema,Eme,Emi,Emo,Emu;
    u64 Esa,Ese,Esi,Eso,Esu;
    Aba=state[0];Abe=state[1];Abi=state[2];Abo=state[3];Abu=state[4];
    Aga=state[5];Age=state[6];Agi=state[7];Ago=state[8];Agu=state[9];
    Aka=state[10];Ake=state[11];Aki=state[12];Ako=state[13];Aku=state[14];
    Ama=state[15];Ame=state[16];Ami=state[17];Amo=state[18];Amu=state[19];
    Asa=state[20];Ase=state[21];Asi=state[22];Aso=state[23];Asu=state[24];
    for (int round = 0; round < KECCAKF_ROUNDS; round += 2) {
        BCa=Aba^Aga^Aka^Ama^Asa;BCe=Abe^Age^Ake^Ame^Ase;
        BCi=Abi^Agi^Aki^Ami^Asi;BCo=Abo^Ago^Ako^Amo^Aso;BCu=Abu^Agu^Aku^Amu^Asu;
        Da=BCu^ROL64(BCe,1);De=BCa^ROL64(BCi,1);Di=BCe^ROL64(BCo,1);Do=BCi^ROL64(BCu,1);Du=BCo^ROL64(BCa,1);
        Aba^=Da;BCa=Aba;Age^=De;BCe=ROL64(Age,44);Aki^=Di;BCi=ROL64(Aki,43);Amo^=Do;BCo=ROL64(Amo,21);Asu^=Du;BCu=ROL64(Asu,14);
        Eba=BCa^((~BCe)&BCi);Eba^=keccakf_rndc[round];Ebe=BCe^((~BCi)&BCo);Ebi=BCi^((~BCo)&BCu);Ebo=BCo^((~BCu)&BCa);Ebu=BCu^((~BCa)&BCe);
        Abo^=Do;BCa=ROL64(Abo,28);Agu^=Du;BCe=ROL64(Agu,20);Aka^=Da;BCi=ROL64(Aka,3);Ame^=De;BCo=ROL64(Ame,45);Asi^=Di;BCu=ROL64(Asi,61);
        Ega=BCa^((~BCe)&BCi);Ege=BCe^((~BCi)&BCo);Egi=BCi^((~BCo)&BCu);Ego=BCo^((~BCu)&BCa);Egu=BCu^((~BCa)&BCe);
        Abe^=De;BCa=ROL64(Abe,1);Agi^=Di;BCe=ROL64(Agi,6);Ako^=Do;BCi=ROL64(Ako,25);Amu^=Du;BCo=ROL64(Amu,8);Asa^=Da;BCu=ROL64(Asa,18);
        Eka=BCa^((~BCe)&BCi);Eke=BCe^((~BCi)&BCo);Eki=BCi^((~BCo)&BCu);Eko=BCo^((~BCu)&BCa);Eku=BCu^((~BCa)&BCe);
        Abu^=Du;BCa=ROL64(Abu,27);Aga^=Da;BCe=ROL64(Aga,36);Ake^=De;BCi=ROL64(Ake,10);Ami^=Di;BCo=ROL64(Ami,15);Aso^=Do;BCu=ROL64(Aso,56);
        Ema=BCa^((~BCe)&BCi);Eme=BCe^((~BCi)&BCo);Emi=BCi^((~BCo)&BCu);Emo=BCo^((~BCu)&BCa);Emu=BCu^((~BCa)&BCe);
        Abi^=Di;BCa=ROL64(Abi,62);Ago^=Do;BCe=ROL64(Ago,55);Aku^=Du;BCi=ROL64(Aku,39);Ama^=Da;BCo=ROL64(Ama,41);Ase^=De;BCu=ROL64(Ase,2);
        Esa=BCa^((~BCe)&BCi);Ese=BCe^((~BCi)&BCo);Esi=BCi^((~BCo)&BCu);Eso=BCo^((~BCu)&BCa);Esu=BCu^((~BCa)&BCe);
        BCa=Eba^Ega^Eka^Ema^Esa;BCe=Ebe^Ege^Eke^Eme^Ese;BCi=Ebi^Egi^Eki^Emi^Esi;BCo=Ebo^Ego^Eko^Emo^Eso;BCu=Ebu^Egu^Eku^Emu^Esu;
        Da=BCu^ROL64(BCe,1);De=BCa^ROL64(BCi,1);Di=BCe^ROL64(BCo,1);Do=BCi^ROL64(BCu,1);Du=BCo^ROL64(BCa,1);
        Eba^=Da;BCa=Eba;Ege^=De;BCe=ROL64(Ege,44);Eki^=Di;BCi=ROL64(Eki,43);Emo^=Do;BCo=ROL64(Emo,21);Esu^=Du;BCu=ROL64(Esu,14);
        Aba=BCa^((~BCe)&BCi);Aba^=keccakf_rndc[round+1];Abe=BCe^((~BCi)&BCo);Abi=BCi^((~BCo)&BCu);Abo=BCo^((~BCu)&BCa);Abu=BCu^((~BCa)&BCe);
        Ebo^=Do;BCa=ROL64(Ebo,28);Egu^=Du;BCe=ROL64(Egu,20);Eka^=Da;BCi=ROL64(Eka,3);Eme^=De;BCo=ROL64(Eme,45);Esi^=Di;BCu=ROL64(Esi,61);
        Aga=BCa^((~BCe)&BCi);Age=BCe^((~BCi)&BCo);Agi=BCi^((~BCo)&BCu);Ago=BCo^((~BCu)&BCa);Agu=BCu^((~BCa)&BCe);
        Ebe^=De;BCa=ROL64(Ebe,1);Egi^=Di;BCe=ROL64(Egi,6);Eko^=Do;BCi=ROL64(Eko,25);Emu^=Du;BCo=ROL64(Emu,8);Esa^=Da;BCu=ROL64(Esa,18);
        Aka=BCa^((~BCe)&BCi);Ake=BCe^((~BCi)&BCo);Aki=BCi^((~BCo)&BCu);Ako=BCo^((~BCu)&BCa);Aku=BCu^((~BCa)&BCe);
        Ebu^=Du;BCa=ROL64(Ebu,27);Ega^=Da;BCe=ROL64(Ega,36);Eke^=De;BCi=ROL64(Eke,10);Emi^=Di;BCo=ROL64(Emi,15);Eso^=Do;BCu=ROL64(Eso,56);
        Ama=BCa^((~BCe)&BCi);Ame=BCe^((~BCi)&BCo);Ami=BCi^((~BCo)&BCu);Amo=BCo^((~BCu)&BCa);Amu=BCu^((~BCa)&BCe);
        Ebi^=Di;BCa=ROL64(Ebi,62);Ego^=Do;BCe=ROL64(Ego,55);Eku^=Du;BCi=ROL64(Eku,39);Ema^=Da;BCo=ROL64(Ema,41);Ese^=De;BCu=ROL64(Ese,2);
        Asa=BCa^((~BCe)&BCi);Ase=BCe^((~BCi)&BCo);Asi=BCi^((~BCo)&BCu);Aso=BCo^((~BCu)&BCa);Asu=BCu^((~BCa)&BCe);
    }
    state[0]=Aba;state[1]=Abe;state[2]=Abi;state[3]=Abo;state[4]=Abu;
    state[5]=Aga;state[6]=Age;state[7]=Agi;state[8]=Ago;state[9]=Agu;
    state[10]=Aka;state[11]=Ake;state[12]=Aki;state[13]=Ako;state[14]=Aku;
    state[15]=Ama;state[16]=Ame;state[17]=Ami;state[18]=Amo;state[19]=Amu;
    state[20]=Asa;state[21]=Ase;state[22]=Asi;state[23]=Aso;state[24]=Asu;
}


struct shake_ctx { u64 st[25]; size_t pos; bool squeezing; };

STATIC void shake_init(struct shake_ctx *S) { memset(S, 0, sizeof(*S)); }

STATIC void shake_absorb(struct shake_ctx *S, const u8 *in, size_t inlen) {
    const size_t rate = 136;
    while (inlen >= rate) {
        for (size_t i = 0; i < rate/8; i++) S->st[i] ^= ((u64)in[i*8]|((u64)in[i*8+1]<<8)|((u64)in[i*8+2]<<16)|((u64)in[i*8+3]<<24)|((u64)in[i*8+4]<<32)|((u64)in[i*8+5]<<40)|((u64)in[i*8+6]<<48)|((u64)in[i*8+7]<<56));
        keccak_f1600(S->st); in += rate; inlen -= rate;
    }
    size_t i;
    for (i = 0; i < inlen/8; i++) S->st[i] ^= ((u64)in[i*8]|((u64)in[i*8+1]<<8)|((u64)in[i*8+2]<<16)|((u64)in[i*8+3]<<24)|((u64)in[i*8+4]<<32)|((u64)in[i*8+5]<<40)|((u64)in[i*8+6]<<48)|((u64)in[i*8+7]<<56));
    S->pos = 8*i; in += S->pos; inlen -= S->pos;
    for (i = 0; i < inlen; i++) { S->st[S->pos>>3] ^= (u64)in[i] << (8*(S->pos&7)); S->pos++; }
}

STATIC void shake_finalize(struct shake_ctx *S) {
    S->st[S->pos>>3] ^= (u64)0x1F << (8*(S->pos&7));
    S->st[(136-1)>>3] ^= (u64)0x80 << (8*((136-1)&7));
    keccak_f1600(S->st); S->pos = 0; S->squeezing = true;
}

STATIC void shake_squeeze(struct shake_ctx *S, u8 *out, size_t outlen) {
    const size_t rate = 136;
    while (outlen > 0) {
        if (S->pos == rate) { keccak_f1600(S->st); S->pos = 0; }
        if ((S->pos&7)==0 && outlen>=8 && S->pos+8<=rate) {
            u64 v=S->st[S->pos>>3]; out[0]=(u8)v;out[1]=(u8)(v>>8);out[2]=(u8)(v>>16);out[3]=(u8)(v>>24);
            out[4]=(u8)(v>>32);out[5]=(u8)(v>>40);out[6]=(u8)(v>>48);out[7]=(u8)(v>>56);
            S->pos+=8; out+=8; outlen-=8; continue;
        }
        *out++ = (u8)(S->st[S->pos>>3] >> (8*(S->pos&7))); S->pos++; outlen--;
    }
}

STATIC void shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen) {
    struct shake_ctx S; shake_init(&S); shake_absorb(&S,in,inlen); shake_finalize(&S); shake_squeeze(&S,out,outlen);
    memset(&S, 0, sizeof(S));
}

STATIC const u16 zetas[HALF_N] = {
    1,1729,2580,3289,2642,630,1897,848,1062,1919,193,797,2786,3260,569,1746,
    296,2447,1339,1476,3046,56,2240,1333,1426,2094,535,2882,2393,2879,1974,821,
    289,331,3253,1756,1197,2304,2277,2055,650,1977,2513,632,2865,33,1320,1915,
    2319,1435,807,452,1438,2868,1534,2402,2647,2617,1481,648,2474,3110,1227,910,
    17,2761,583,2649,1637,723,2288,1100,1409,2662,3281,233,756,2156,3015,3050,
    1703,1651,2789,1789,1847,952,1461,2687,939,2308,2437,2388,733,2337,268,641,
    1584,2298,2037,3220,375,2549,2090,1645,1063,319,2773,757,2099,561,2466,2594,
    2804,1092,403,1026,1143,2150,2775,886,1722,1212,1874,1029,2110,2935,885,2154
};

STATIC const u16 gammas[HALF_N] = {
    17,3312,2761,568,583,2746,2649,680,1637,1692,723,2606,2288,1041,1100,2229,
    1409,1920,2662,667,3281,48,233,3096,756,2573,2156,1173,3015,314,3050,279,
    1703,1626,1651,1678,2789,540,1789,1540,1847,1482,952,2377,1461,1868,2687,642,
    939,2390,2308,1021,2437,892,2388,941,733,2596,2337,992,268,3061,641,2688,
    1584,1745,2298,1031,2037,1292,3220,109,375,2954,2549,780,2090,1239,1645,1684,
    1063,2266,319,3010,2773,556,757,2572,2099,1230,561,2768,2466,863,2594,735,
    2804,525,1092,2237,403,2926,1026,2303,1143,2186,2150,1179,2775,554,886,2443,
    1722,1607,1212,2117,1874,1455,1029,2300,2110,1219,2935,394,885,2444,2154,1175
};

STATIC void ntt_fwd(u16 f[N]) {
    u16 idx = 1;
    for (u16 len = HALF_N; len >= 2; len >>= 1)
        for (u16 start = 0; start < N; start += 2*len) {
            u16 z = zetas[idx++];
            for (u16 j = start; j < start+len; j++) {
                u16 t = mul_mod(z, f[j+len]);
                f[j+len] = sub_mod(f[j], t);
                f[j] = add_mod(f[j], t);
            }
        }
}

STATIC void ntt_inv(u16 f[N]) {
    u16 idx = HALF_N - 1;
    for (u16 len = 2; len <= HALF_N; len <<= 1)
        for (u16 start = 0; start < N; start += 2*len) {
            u16 z = zetas[idx--];
            for (u16 j = start; j < start+len; j++) {
                u16 t = f[j], u = f[j+len];
                f[j] = add_mod(t, u);
                f[j+len] = mul_mod(z, sub_mod(u, t));
            }
        }
    for (u16 j = 0; j < N; j++) f[j] = mul_mod(f[j], 169);
}

STATIC void poly_mul_ntt(u16 out[N], const u16 a[N], const u16 b[N]) {
    for (u16 i = 0; i < HALF_N; i++) {
        u16 a0=a[2*i],a1=a[2*i+1],b0=b[2*i],b1=b[2*i+1];
        u16 t0=mul_mod(a0,b0), t1=mul_mod(mul_mod(a1,b1),gammas[i]);
        out[2*i] = add_mod(t0, t1);
        out[2*i+1] = add_mod(mul_mod(a0,b1), mul_mod(a1,b0));
    }
}

struct coset_tag_ctx {
    int16_t d[COEFFS]; 
};

STATIC int default_entropy(void *buf, size_t len) {
#ifdef __linux__
    return (getrandom(buf, len, 0) == (ssize_t)len) ? 0 : -1;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
#endif
}

coset_tag_ctx *coset_tag_create(int (*entropy_fn)(void *, size_t)) {
    coset_tag_ctx *ctx = calloc(1, sizeof(coset_tag_ctx));
    if (!ctx) return NULL;
    if (!entropy_fn) entropy_fn = default_entropy;

    
    u8 seed[32];
    if (entropy_fn(seed, 32) != 0) { free(ctx); return NULL; }
    u8 expanded[COEFFS * 2];
    shake256(expanded, sizeof(expanded), seed, 32);
    memset(seed, 0, sizeof(seed));

    for (size_t i = 0; i < COEFFS; i++) {
        u16 val = ((u16)expanded[2*i] << 8) | expanded[2*i+1];
        ctx->d[i] = (int16_t)((val % (2 * COSET_TAG_B_D + 1)) - COSET_TAG_B_D);
    }
    memset(expanded, 0, sizeof(expanded));
    return ctx;
}

void coset_tag_destroy(coset_tag_ctx *ctx) {
    if (!ctx) return;
    volatile int16_t *vd = (volatile int16_t *)ctx->d;
    for (size_t i = 0; i < COEFFS; i++) vd[i] = 0;
    free(ctx);
}

STATIC void hash_to_ternary(const u8 *msg, size_t msg_len, int16_t *out) {
    size_t dlen = strlen(COSET_TAG_DOMAIN);
    size_t total = msg_len + dlen;
    u8 *buf = malloc(total);
    if (!buf) { memset(out, 0, COEFFS * sizeof(int16_t)); return; }
    memcpy(buf, msg, msg_len);
    memcpy(buf + msg_len, COSET_TAG_DOMAIN, dlen);
    u8 raw[COEFFS * 2];
    shake256(raw, sizeof(raw), buf, total);
    free(buf);
    for (size_t i = 0; i < COEFFS; i++) {
        u16 val = ((u16)raw[2*i] << 8) | raw[2*i+1];
        out[i] = (int16_t)((val % 3) - 1);
    }
    memset(raw, 0, sizeof(raw));
}

STATIC void compute_z(int16_t *z, const int16_t *u_signed, const int16_t *d, const int16_t *alpha) {
    for (int k = 0; k < K; k++) {
        u16 d_ntt[N], a_ntt[N], prod_ntt[N];
        for (int i = 0; i < N; i++) {
            d_ntt[i] = to_unsigned(d[k*N + i]);
            a_ntt[i] = to_unsigned(alpha[k*N + i]);
        }
        ntt_fwd(d_ntt); ntt_fwd(a_ntt);
        poly_mul_ntt(prod_ntt, d_ntt, a_ntt);
        ntt_inv(prod_ntt);
        for (int i = 0; i < N; i++) {
            int16_t prod = to_signed(prod_ntt[i]);
            z[k*N + i] = (int16_t)((u_signed[k*N + i] + prod) % Q);
            if (z[k*N + i] > Q/2) z[k*N + i] -= Q;
            if (z[k*N + i] < -(Q/2)) z[k*N + i] += Q;
        }
    }
}

void coset_tag_pack(const int16_t *coeffs, size_t n, u8 *out) {
    size_t byte_len = n * 12 / 8;
    memset(out, 0, byte_len);
    for (size_t i = 0; i < n; i++) {
        u16 val = to_unsigned(coeffs[i]);
        size_t bit_pos = i * 12;
        size_t byte_pos = bit_pos / 8;
        size_t bit_off = bit_pos % 8;
        u32 shifted = (u32)val << bit_off;
        out[byte_pos] |= (u8)(shifted & 0xFF);
        if (byte_pos+1 < byte_len) out[byte_pos+1] |= (u8)((shifted>>8) & 0xFF);
        if (byte_pos+2 < byte_len) out[byte_pos+2] |= (u8)((shifted>>16) & 0xFF);
    }
}

void coset_tag_unpack(const u8 *in, size_t byte_len, int16_t *coeffs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        size_t bit_pos = i * 12;
        size_t byte_pos = bit_pos / 8;
        size_t bit_off = bit_pos % 8;
        u32 val = 0;
        val |= (u32)in[byte_pos];
        if (byte_pos+1 < byte_len) val |= (u32)in[byte_pos+1] << 8;
        if (byte_pos+2 < byte_len) val |= (u32)in[byte_pos+2] << 16;
        val = (val >> bit_off) & 0xFFF;
        coeffs[i] = (val > Q/2) ? (int16_t)(val - Q) : (int16_t)val;
    }
}

int coset_tag_generate(const coset_tag_ctx *ctx,
                       const u8 *u_bytes, size_t u_len,
                       const u8 *msg, size_t msg_len,
                       u8 *z_out, size_t z_out_len) {
    if (!ctx || !u_bytes || !msg || !z_out) return -1;
    if (u_len != COSET_TAG_BYTES || z_out_len != COSET_TAG_BYTES) return -1;

    int16_t u_signed[COEFFS];
    coset_tag_unpack(u_bytes, u_len, u_signed, COEFFS);

    int16_t alpha[COEFFS];
    hash_to_ternary(msg, msg_len, alpha);

    int16_t z[COEFFS];
    compute_z(z, u_signed, ctx->d, alpha);

    coset_tag_pack(z, COEFFS, z_out);

    memset(u_signed, 0, sizeof(u_signed));
    memset(alpha, 0, sizeof(alpha));
    memset(z, 0, sizeof(z));
    return 0;
}

int coset_tag_verify(const coset_tag_ctx *ctx,
                     const u16 *true_u, size_t u_coeffs,
                     const u8 *msg, size_t msg_len,
                     const u8 *z_bytes, size_t z_len) {
    if (!ctx || !true_u || !msg || !z_bytes) return -1;
    if (u_coeffs != COEFFS || z_len != COSET_TAG_BYTES) return -1;

    int16_t u_signed[COEFFS];
    for (size_t i = 0; i < COEFFS; i++)
        u_signed[i] = (true_u[i] > Q/2) ? (int16_t)(true_u[i] - Q) : (int16_t)true_u[i];

    int16_t alpha[COEFFS];
    hash_to_ternary(msg, msg_len, alpha);
    int16_t z_expected[COEFFS];
    compute_z(z_expected, u_signed, ctx->d, alpha);

    int16_t z_received[COEFFS];
    coset_tag_unpack(z_bytes, z_len, z_received, COEFFS);

    volatile u32 diff = 0;
    for (size_t i = 0; i < COEFFS; i++) {
        int16_t d = z_expected[i] - z_received[i];
        d = (int16_t)((d % Q + Q) % Q);
        diff |= (d != 0) ? 1 : 0;
    }

    memset(u_signed, 0, sizeof(u_signed));
    memset(alpha, 0, sizeof(alpha));
    memset(z_expected, 0, sizeof(z_expected));
    memset(z_received, 0, sizeof(z_received));
    return (diff == 0) ? 0 : -1;
}

int coset_tag_get_d(const coset_tag_ctx *ctx, int16_t *d_out, size_t d_coeffs) {
    if (!ctx || !d_out || d_coeffs < COEFFS) return -1;
    memcpy(d_out, ctx->d, COEFFS * sizeof(int16_t));
    return 0;
}
