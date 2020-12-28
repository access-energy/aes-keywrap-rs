# AES Key Wrap for Rust

This crate is an AES Keywrap (RFC 3394 / RFC 5649) implementation for Rust.

It has implemented AES KeyWrap(128/192/256 ECB mode) using [Crypto2](https://github.com/shadowsocks/crypto2).

## Usage

```rust
let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
let cipher = hex::decode("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1").unwrap();
let plain = hex::decode("00112233445566778899AABBCCDDEEFF0001020304050607").unwrap();
aes_wrap_key(&kek, &plain);
```

## References

- [RFC3394](https://www.ietf.org/rfc/rfc3394.txt)
  - Advanced Encryption Standard (AES) Key Wrap Algorithm
- [RFC5649](https://www.ietf.org/rfc/rfc5649.txt)
  - Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm
- [Rust AES Keywrap](https://github.com/jedisct1/rust-aes-keywrap)
  - It doesn't support RFC3394 and RFC5649 now. [issue #2](https://github.com/jedisct1/rust-aes-keywrap/issues/2)
- [aes-keywrap-py](https://github.com/kurtbrose/aes_keywrap/blob/master/aes_keywrap.py)
  - Strongly inspired by this python module.
- [AesKeyWrap(C++)](https://github.com/ikluft/AESKeyWrap/blob/master/src/AesKeyWrap.cpp) and [AesKeyWrap Test(C++)](https://github.com/ikluft/AESKeyWrap/blob/master/test/AesKeyWrapTest.cpp)
- [(C++) AES Key Wrap / Unwrap example](https://www.example-code.com/cpp/aes_key_wrap.asp)
- FreeBSD Crypto
  - [aes-wrap.c](http://web.mit.edu/freebsd/head/contrib/wpa/src/crypto/aes-wrap.c)
  - [aes-unwrap.c](http://web.mit.edu/freebsd/head/contrib/wpa/src/crypto/aes-unwrap.c)

## License

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
