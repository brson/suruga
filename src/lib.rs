#![crate_type = "lib"]
#![crate_name = "suruga"]

#![allow(missing_copy_implementations)]

#![feature(slicing_syntax)]
#![feature(core, collections, rand, io)]

#[macro_use]
extern crate log;

extern crate chrono;

pub use tls::Tls;
pub use client::TlsClient;

#[macro_use]
pub mod macros;
pub mod util;

// basic crypto primitives
pub mod crypto {
    pub mod sha2;
    pub mod p256;
    pub mod poly1305;
    pub mod chacha20;
}

pub mod tls_result;
#[macro_use]
pub mod tls_item;
pub mod record;

// TLS AEAD cipehrsuites
pub mod cipher;

pub mod signature;
pub mod alert;
pub mod handshake;

pub mod tls;
pub mod client;

#[macro_use]
pub mod der;
#[macro_use]
pub mod x509;

#[cfg(test)] mod test;
