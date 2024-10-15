Handshake Internals
===================

*This document is still a work-in-progress, for more details see [handshake.rs](handshake/src/handshake.rs)*

Hyphae allows you to secure QUIC with a Noise handshake, from the
[Noise Protocol Framework](https://noiseprotocol.org/noise.html). 
Hyphae supports all Noise handshake patterns and allows the application
to send custom payloads with every message.

Securing QUIC with a Noise handshake is a bit of an exercise in fitting
a square peg into a round hole because of Noise's simplicity and QUIC's
requirements:

1. QUIC uses the handshake to transmit the connection transport
   parameters and requires them to be part of the handshake transcript.
   This data needs to be combined with the application's Noise payloads.

2. QUIC needs a forward-secure secret as early in the handshake as
   possible to transition from the obfuscated initial packet space to
   the encrypted handshake packet space. The Noise ASK proposal can
   generate this secret but there is still some complication to avoid
   sending the second Noise message's payload in the initial packet
   space.

To satisfy these requirements, Hyphae rearranges the first two Noise
handshake payloads – though not in a way that alters their security
properties described in [Section 7.7](https://noiseprotocol.org/noise.html#payload-security-properties)
of the protocol framework.

Hyphae uses the proposed ASK [\(Additional Symmetric Keys\)](https://github.com/noiseprotocol/noise_wiki/wiki/Additional-Symmetric-Keys)
extension to generate the additional keys needed by QUIC.

Handshake Messages
------------------

Handshake messages consist of a single byte identifier followed by the
contents of the message. Most of these messages are from the underlying
Noise handshake, but there are a few extras. These messages must be
delivered in order.

- Preamble: Optional, unprotected application specific preamble sent by
  the initiator. This can be used by the responder to select a Noise
  protocol for the handshake if it supports more than one. If an initial
  message is received first, the preamble is empty. 
  `ID: 1`
- Initial: Contains the first two Noise messages in the handshake, sent
  in the initial packet space.
  `ID: 2`
- Deferred Payload: Contains the actual payload data of the second Noise
  message (more on this below). Sent in the handshake packet space.
  `ID: 3`
- Noise: Used in handshake patterns with more than two messages.
  Contains the third and subsequent Noise messages. Sent in the
  handshake packet space. 1-RTT keys are generated after the last Noise
  message.
  `ID: 4`
- Final or FinalPayload: Sent after the Noise handshake is finished.
  The payload variant can be used to carry one last payload in each
  direction. Sent in the 1-RTT packet space. Application data can be
  sent after the last Noise message, it does not wait for final messages
  to be received.
  `IDs: 127, 126`
- Failed: Aborts the handshake. Should only be used if QUIC's close
  message cannot be sent.
  `ID: 255`

Noise Handshake and Payloads
----------------------------

This section describes how Hyphae transforms Noise handshakes.

A Noise handshake consists of a protocol, prologue, and a payload for
each message in the handshake pattern. For example, `Noise_XX`:

```
PROTOCOL: "Noise_XX_25519_ChaChaPoly_BLAKE2s"
PROLOGUE: APP_PROLOGUE

-> e, APP_PAYLOAD_1
<- e, ee, s, es, APP_PAYLOAD_2
-> s, se, APP_PAYLOAD_3
```

This becomes the following Hyphae handshake:

```
-> Preamble:
   Optional preamble, empty if not sent

PROTOCOL: "Noise_XX_25519_ChaChaPoly_BLAKE2s"
PROLOGUE:
    HANDSHAKE_VERSION .. "." ..
    TRANSPORT_LABEL .. "." ..
    PREAMBLE_LEN_U16_LE .. PREAMBLE ..
    APP_PROLOGUE
HANDSHAKE_VERSION: "hyphae-h-v1"
TRANSPORT_LABEL: "quic-v1"

-> Initial:
   e, COMPOUND_INITIATOR_CONFIG_PAYLOAD(APP_PAYLOAD_1)
<- Initial:
   e, ee, s, es, DEFERRED_PAYLOAD_HASH

** [Transition to Handshake Packet Space]

<- Deferred Payload:
   COMPOUND_RESPONDER_CONFIG_PAYLOAD(APP_PAYLOAD_2)

-> Noise:
   s, se, APP_PAYLOAD_3

** [Transition to 1-RTT Packet Space]

-> Final or FinalPayload
<- Final or FinalPayload (final messages can be sent in any order)
```

The format of the compound payloads are not documented yet but can be
found in [handshake.rs](handshake/src/handshake.rs).

### Payload Security Properties

- The initial packet space is only obfuscated with a key based on the
  QUIC client connection ID (like in QUIC-TLS). As such:
  - The preamble is essentially sent as plain-text
  - The COMPOUND_INITIATOR_CONFIG_PAYLOAD has the same security properties
    the first Noise payload. E.g. 0-RTT encrypted in "*K" handshakes
    and unencrypted in others.
- The entire handshake packet space has the same security properties
  as the second Noise payload.
  - The hash of the deferred payload is validated by Hyphae.
- Subsequent Noise messages are still encrypted as usual inside the
  handshake packet space. As such, their payloads have the usual
  security properties for that handshake pattern.
- The 1-RTT data has the security properties of the completed Noise
  handshake.
  - Final messages are sent in the 1-RTT packet space.

Key Derivation
--------------

An encryption level secret is generated for each packet space. The
handshake and 1-RTT packet space secrets are generated with the Noise
ASK proposal (using the label "hyphae key"):

- The handshake key is generated after the second Noise message.
- The 1-RTT key is generated after the last Noise message. This is the
  second Noise message for some patterns. In this case, Hyphae uses
  the next key in the ASK chain created to generate the handshake
  key.

### Sub Keys

Each level secret is split into four keys using the Noise protocol's
`HKDF` with an empty salt, `IKM` of the level secret, and a sub-key
specific `info`:

- Initiator packet protection key: `info: "init data"`
- Responder packet protection key: `info: "resp data"`
- Initiator header protection key: `info: "init hp"`
- Responder header protection key: `info: "resp hp"`

Unlike QUIC-TLS, Noise does not use random IVs, so none are calculated
here.

### Initial Keys

Like QUIC-TLS, Hyphae obfuscated the initial packet space with a key
based on the original client connection ID. Since the Noise protocol
isn't known at this time, `ChaChaPoly` and `BLAKE2s` are always used as
the AEAD and hash algorithm for the initial packet space.

The initial level secret is calculated using `HKDF` with an empty salt,
`info: "hyphae initial"` and the following `IKM`:

```
IKM:
    HANDSHAKE_VERSION .. "." ..
    TRANSPORT_LABEL .. "." ..
    CLIENT_ORIG_DCID

HANDSHAKE_VERSION: "hyphae-h-v1"
TRANSPORT_LABEL: "quic-v1"
```

Sub-keys for the initial packet space are calculated as described above.

### 1-RTT Rekey

1-RTT rekey is accomplished by generating new level secrets from the
`"hyphae key"` ASK chain. During rekey, only new packet protection keys
are generated.

Packet Protection
-----------------

Packet protection is applied to each QUIC payload as described in
[Out-of-order transport messages](https://noiseprotocol.org/noise.html#out-of-order-transport-messages)
in the Noise protocol framework with that side's packet protection key
for the packet space. The packet number is used as the nonce.

### Header Protection

Header protection is applied exactly as it is in QUIC-TLS for ChaChaPoly
and AES256-GCM. See [RFC 9001: Header Protection](https://datatracker.ietf.org/doc/html/rfc9001#name-header-protection).

### Retry Integrity Tag

Retry integrity tags are calculated differently from QUIC-TLS. See the
`retry_tag` method in [quinn-hyphae's config.rs](quinn/src/config.rs)
for more details.

QUIC Version Number
-------------------

QUIC version 1 [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
secured with Hyphae Handshake version 1 uses the version number
`0x48510101` (big-endian), handshake version label: `"hyphae-h-v1"` and
transport label: `"quic-v1"`.

See [hyphae-handshake's quic.rs](handshake/src/quic.rs) for more info.
