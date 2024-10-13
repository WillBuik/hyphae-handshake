Hyphae Handshake (*Noise Handshakes for QUIC*)
==============================================

Hyphae secures QUIC with Noise instead of TLS.

Unlike other Noise hanshake proposals for QUIC, Hyphae supports *all
Noise handshake patterns* (not just IK). Hyphae supports custom Noise
payloads.

### Features:

- Secure QUIC connections with a Noise handshake instead of TLS
- Use **any handshake pattern**, AEAD, and hash algorithm (not just IK)
- Quinn support in the `quinn-hyphae` crate
- Customizable:
  - Applications have complete control of the Noise handshake
  - Pluggable cryptographic and Noise backends (with built-in support
    for Rust Crypto)
- Optional key-logging for diagnostics
- QUIC header protection and initial packet space obfustication

### Crates

- **quinn-hyphae**: Hyphae support for Quinn. This is all you need to
  to get started.

- **hyphae-hanshake**: The low-level guts of the Hyphae hanshake. You
  don't need to import this unless you are implementing a custom
  cryptographic backend or adding support for another QUIC library.
  For typical use, the `quinn-hyphae` crate re-exports everything you
  will need from this.

### Minumum Rust Version

Hyphae uses the `core::error::Error` trait so it needs Rust version
`1.81` or higher to build.

Usage with Quinn
================

Basic Noise handshake flows are extremely easy to set up with Hyphae.
Here we set up a `quinn::Endpoint` in just seven lines of code:

```rust
use quinn_hyphae::{
    HandshakeBuilder,
    RustCryptoBackend,
    helper::hyphae_server_endpoint
};

// Set up a `quinn::Endpoint` server with a Noise XX handshake:
let secret_key = RustCryptoBackend.new_secret_key(&mut rand_core::OsRng);
let crypto_config = 
    HandshakeBuilder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s")
    .with_static_key(&secret_key)
    .build(RustCryptoBackend)?;

let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
let endpoint = hyphae_server_endpoint(crypto_config, None, socket)?;
```

It is also easy to set up bidirectional endpoints that validate a peer's
public key for outgoing connections:

```rust
let secret_key = RustCryptoBackend.new_secret_key(&mut rand_core::OsRng);
let crypto_config = 
    HandshakeBuilder::new("Noise_XK_25519_ChaChaPoly_BLAKE2s")
    .with_static_key(&secret_key)
    .with_server_name_as_remote_public()
    .build(RustCryptoBackend)?;

let socket = UdpSocket::bind("127.0.0.1:0")?;
let endpoint = hyphae_bidirectional_endpoint(crypto_config, None, socket)?;

// The peer's public key parsed from `server_name` and validated during
// the handshake.
let conn = endpoint.connect(peer_addr, "zR4F09MibpGVw/L9oDvuItojQ/9MOSCt9mMK0kUNggA=")?.await?;
```

There are more [examples](quinn/examples) in the `quinn-hyphae` crate.

### Default Quinn Features

If you are not going to use TLS, you can disable all of Quinn's default
features (except for your async runtime of choice). The `quinn-hyphae`
crate provides the cryptographic backend.

How Hyphae Works
================

Hyphae hanshakes look like an unmodified Noise hanshake to your
application. Under the hood, a few things are going on to make this
work smoothly with QUIC:

- Noise's proposed extesnsion for Additional Symmetric Key generation
  is used to generate the extra keys QUIC needs.
- Hyphae adds some additional data (e.g. QUIC transport parameters)
  to the first two Noise payloads.
- Optional preamble and final messages can be sent before and after
  the Noise handshake if needed.
- Framed handshake messages are sent over the QUIC CRYPTO stream.

The selected Noise protocol's AEAD is used to provide packet and header
protection for the handshake and 1-RTT packet spaces.

All of the nitty-gritty details of the Hyphae hanshake are described
[here](HANDSHAKE.md).

Roadmap:
========

The basic functionality of Hyphae is finished, but a few things are on
the roadmap:

- Noise PSK modifier
- Noise HFS extension support (post-quantum KEM)
- Other crypto backends (ring, aws-lc-rs)
- QUIC 0-RTT
- Packet decryption utilities (SSLKEYLOGFILE-like functionality)

Hyphae's built-in Noise implementation only supports X25519. Built-in
support for other curves isn't planned, but the crypto backend traits
are flexible enough to support them.

### Non-goals:

Hyphae isn't a TLS replacement and doesn't have built-in support for:

- Algorithm negotiation
  - Both sides need to agree on the Noise protocol in advance
  - An optional `preamble` message can be sent by the initiator to
    facilitate this
- Handshake extensions like `ALPN`
  - That said, your application is free to put whatever it needs into
    the Noise payloads

