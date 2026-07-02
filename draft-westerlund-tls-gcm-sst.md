---
title: "Use of Galois Counter Mode with Strong Secure Tags (GCM-SST) in TLS, DTLS and QUIC"
abbrev: "GCM-SST in TLS, DTLS and QUIC"
category: std

docname: draft-westerlund-tls-gcm-sst-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - TLS
 - QUIC
 - Cipher Suite
 - GCM-SST

venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "gloinul/draft-westerlund-tls-gsm-sst"
  latest: "https://gloinul.github.io/draft-westerlund-tls-gsm-sst/draft-westerlund-tls-gsm-sst.html"

author:
 -
   ins:  M. Westerlund
   name: Magnus Westerlund
   org: Ericsson
   email: magnus.westerlund@ericsson.com

 -
   ins: J. Preuß Mattsson
   name: John Preuß Mattsson
   org: Ericsson
   email: john.mattsson@ericsson.com

normative:

  I-D.draft-mattsson-cfrg-aes-gcm-sst:

informative:

--- abstract

This document defines cipher suites based on AES-GCM-SST and Rijndael-GCM-SST (Galois Counter Mode with Strong Secure Tags) for use in TLS 1.3, DTLS 1.3, and QUIC. GCM-SST provides authenticated encryption with near-ideal forgery probabilities for short authentication tags, making it suitable for bandwidth-constrained environments where reduced per-packet overhead is important. This document specifies cipher suites with 96-bit and 112-bit authentication tags.

--- middle

# Introduction

AES-GCM-SST and Rijndael-GCM-SST {{I-D.draft-mattsson-cfrg-aes-gcm-sst}} are Authenticated Encryption with Associated Data (AEAD) algorithms that provide near-ideal forgery probabilities even with short authentication tags. This makes them particularly suitable for use cases where bandwidth is constrained and reduced per-packet overhead is desirable, such as real-time media, IoT communications, and constrained radio networks.

Standard AES-GCM with short tags has well-known weaknesses that significantly increase forgery probabilities, especially under multiple forgery attacks. GCM-SST addresses these weaknesses through the introduction of an additional subkey and per-nonce subkey derivation, following recommendations from Nyberg et al.

Rijndael-GCM-SST uses Rijndael-256 (256-bit block size) as the keystream generator, providing a 28-byte nonce and significantly higher security margins against precomputation and multi-key attacks compared to AES-GCM-SST.

This document specifies how AES-GCM-SST and Rijndael-GCM-SST algorithms are integrated into TLS 1.3 {{!RFC8446}}, DTLS 1.3 {{!RFC9147}}, and QUIC {{!RFC9000}}, defining new cipher suites and the necessary procedures for record number encryption and header protection.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# New Cipher Suites

The cipher suites and cryptographic negotiation mechanisms established in TLS 1.3 are reused by the DTLS 1.3 and QUIC protocols.

This document introduces the following cipher suites based on AES-GCM-SST:

| Cipher Suite Name | AEAD Algorithm | Hash Algorithm | Tag Length (bits) |
| --- | --- | --- | --- |
| `TLS_AES_128_GCM_SST_12_SHA256` | AEAD_AES_128_GCM_SST_12 | SHA256 | 96 |
| `TLS_AES_128_GCM_SST_14_SHA256` | AEAD_AES_128_GCM_SST_14 | SHA256 | 112 |
| `TLS_AES_256_GCM_SST_12_SHA384` | AEAD_AES_256_GCM_SST_12 | SHA384 | 96 |
| `TLS_AES_256_GCM_SST_14_SHA384` | AEAD_AES_256_GCM_SST_14 | SHA384 | 112 |
| `TLS_RIJNDAEL_GCM_SST_12_SHA384` | AEAD_RIJNDAEL_GCM_SST_12 | SHA384 | 96 |
| `TLS_RIJNDAEL_GCM_SST_14_SHA384` | AEAD_RIJNDAEL_GCM_SST_14 | SHA384 | 112 |
{: title="GCM-SST cipher suites for TLS 1.3"}

The AEAD algorithms are defined in {{I-D.draft-mattsson-cfrg-aes-gcm-sst}}. The number in the cipher suite name after "SST" indicates the tag length in bytes (12 or 14).

The 256-bit key variants (AES-256 and Rijndael) use SHA384 as the hash algorithm for HKDF to provide a security margin consistent with the larger key size.

The Rijndael-GCM-SST variants use a 28-byte nonce, which provides significantly greater security against precomputation and multi-key attacks compared to the AES variants with their 12-byte nonce.

With the inclusion of these new cipher suites, the cryptographic negotiation mechanism in TLS 1.3, as outlined in {{!RFC8446, Section 4.1.1}}, remains unchanged, as does the record payload protection mechanism specified in {{!RFC8446, Section 5.2}}.

# TLS 1.3 Record Payload Protection

When a GCM-SST cipher suite is negotiated, record payload protection follows {{!RFC8446, Section 5.2}} using the negotiated AEAD algorithm.

The per-record nonce is constructed as specified in {{!RFC8446, Section 5.3}}: the 64-bit record sequence number is padded with leading zeros to the nonce length and XORed with the write_iv derived from the traffic secret. The nonce length is 12 bytes for AES-GCM-SST cipher suites and 28 bytes for Rijndael-GCM-SST cipher suites.

The encrypted record has the following structure:

~~~
struct {
    opaque content[TLSPlaintext.length];
    ContentType type;
    uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct {
    ContentType opaque_type = application_data; /* 23 */
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    uint16 length;
    opaque encrypted_record[TLSInnerPlaintext.length + tag_length];
} TLSCiphertext;
~~~

The tag_length is 12 or 14 bytes depending on the negotiated cipher suite.

# DTLS 1.3 Record Number Encryption

In DTLS 1.3, encryption of record sequence numbers follows the specification in {{!RFC9147, Section 4.2.3}}.

## AES-GCM-SST Cipher Suites

For AES-GCM-SST cipher suites, the mask used for sequence number encryption is generated using AES-ECB with:

- `sn_key`: the sequence number encryption key as defined in {{!RFC9147, Section 4.2.3}}
- `ciphertext[0..15]`: the first 16 bytes of the DTLS ciphertext

The mask is computed as follows:

~~~
mask = AES-ECB(sn_key, ciphertext[0..15])
~~~

This is the same mechanism used for AES-GCM and AES-CCM cipher suites in DTLS 1.3.

## Rijndael-GCM-SST Cipher Suites

For Rijndael-GCM-SST cipher suites, the mask is generated using Rijndael-256-ECB with:

- `sn_key`: the sequence number encryption key as defined in {{!RFC9147, Section 4.2.3}}
- `ciphertext[0..31]`: the first 32 bytes of the DTLS ciphertext

The mask is computed as follows:

~~~
mask = Rijndael-256-ECB(sn_key, ciphertext[0..31])
~~~

The first 16 bits of the mask are used to encrypt the sequence number, following the procedure in {{!RFC9147, Section 4.2.3}}.

# QUIC Header Protection

In QUIC, specific segments of the packet header are protected as specified in {{!RFC9001, Section 5.4}}.

## AES-GCM-SST Cipher Suites

For AES-GCM-SST cipher suites, the header protection mask is generated using AES-ECB with:

- `hp_key`: the header protection key as defined in {{!RFC9001, Section 5.4.3}}
- `sample`: a 16-byte sample from the packet payload ciphertext

The 5-byte mask is computed as follows:

~~~
mask = AES-ECB(hp_key, sample)[0..4]
~~~

This is the same mechanism used for AES-GCM cipher suites in QUIC, as specified in {{!RFC9001, Section 5.4.3}}.

## Rijndael-GCM-SST Cipher Suites

For Rijndael-GCM-SST cipher suites, the header protection mask is generated using Rijndael-256-ECB with:

- `hp_key`: the header protection key as defined in {{!RFC9001, Section 5.4.3}}
- `sample`: a 32-byte sample from the packet payload ciphertext

The 5-byte mask is computed as follows:

~~~
mask = Rijndael-256-ECB(hp_key, sample)[0..4]
~~~

# Key Update and Usage Limits

A key update MUST be performed prior to reaching the usage limits specified in {{I-D.draft-mattsson-cfrg-aes-gcm-sst}}. The key update mechanism is documented in {{!RFC8446, Section 4.6.3}}.

For AES-GCM-SST, the confidentiality and integrity limits depend on the specific AEAD instance. Protocols utilizing AES-GCM-SST MUST ensure that (P_MAX + A_MAX) * (Q_MAX + V_MAX) does not exceed approximately 2^66, as specified in {{I-D.draft-mattsson-cfrg-aes-gcm-sst}}.

In TLS 1.3 and QUIC, where record/packet payloads are limited to approximately 2^14 bytes, a key update MUST be performed before encrypting 2^32 records with the same key for AES-GCM-SST cipher suites.

For Rijndael-GCM-SST cipher suites, the usage limits are significantly higher (Q_MAX = V_MAX = 2^88), and a key update MUST be performed before encrypting 2^88 records with the same key.

The number of failed decryption attempts (forgery attempts) before a key update or connection termination SHOULD be limited.

# Operational Considerations

The cipher suites defined in this document use 96-bit or 112-bit tags. For general-purpose use, cipher suites with 112-bit tags are RECOMMENDED.

Rijndael-GCM-SST cipher suites offer significantly higher usage limits and stronger multi-key security compared to AES-GCM-SST, at the cost of requiring Rijndael-256 hardware support for optimal performance.

On devices lacking hardware AES acceleration, cipher suites dependent on the AES round function SHOULD NOT be prioritized.

On devices equipped with hardware AES acceleration, GCM-SST cipher suites provide performance comparable to standard AES-GCM cipher suites while offering improved integrity guarantees for a given tag length.

# Security Considerations

The security properties of GCM-SST are detailed in {{I-D.draft-mattsson-cfrg-aes-gcm-sst}}. The key security advantages over standard AES-GCM with equivalent tag lengths are:

- Near-ideal forgery probability of approximately 1/2^tag_length, even for long messages.
- Resistance to multiple forgery attacks (reforgeability resistance).
- Per-nonce subkey derivation prevents key recovery from successful forgeries.

GCM-SST MUST be used in a nonce-respecting setting. Nonce reuse enables universal forgery. The nonce construction in TLS 1.3 (XOR of sequence number with per-key IV) satisfies this requirement.

The 96-bit tag cipher suites provide a forgery probability of approximately 2^-96 per attempt, which is suitable for most applications. The 112-bit tag cipher suites provide an even higher security margin.

# IANA Considerations

IANA is requested to assign identifiers in the TLS Cipher Suite Registry for the following cipher suites:

| Value | Description | DTLS-OK | Recommended |
| :---: | :---------- | :-----: | :---------: |
| TBD | `TLS_AES_128_GCM_SST_12_SHA256` | Y | N |
| TBD | `TLS_AES_128_GCM_SST_14_SHA256` | Y | N |
| TBD | `TLS_AES_256_GCM_SST_12_SHA384` | Y | N |
| TBD | `TLS_AES_256_GCM_SST_14_SHA384` | Y | N |
| TBD | `TLS_RIJNDAEL_GCM_SST_12_SHA384` | Y | N |
| TBD | `TLS_RIJNDAEL_GCM_SST_14_SHA384` | Y | N |
{: title="IANA cipher suite assignments"}

--- back

# Acknowledgments
{:numbered="false"}

This document is based on draft-denis-tls-aegis. The authors would like to thank Frank Denis and Samuel Lucas for their work on that document.
