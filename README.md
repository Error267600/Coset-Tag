# Coset-Tag
Post quantum asymmetric authentication tag used for point to point.
## Attribution

This project embeds ML-KEM primitives from [kstzv/ml-kem](https://github.com/kstzv/ml-kem):

> Copyright (c) 2026 kstzv
> Licensed under MIT OR GPL-2.0
> https://github.com/kstzv/ml-kem

Embedded components:
- Keccak-f[1600] permutation (`keccak_f1600`)
- SHAKE128/SHAKE256 sponge construction
- NTT/INTT with FIPS-203 zeta and gamma tables
- ML-KEM-512 key generation, encapsulation, decapsulation
- Decapsulation pool management
- Userspace platform abstraction layer
