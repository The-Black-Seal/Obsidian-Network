# Vendored data

## `bip39_english.txt`

The standard BIP-39 English word list (2048 words), used to encode Obsidian
wallet recovery phrases.  The list is part of the BIP-39 specification
(https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md)
and is distributed under the same terms as BIP-39 (public domain / MIT).

The file is vendored rather than downloaded so that builds are reproducible and
offline-verifiable.  Its SHA-256 checksum is asserted by a unit test in
`src/mnemonic.rs`.

Authoritative checksum:
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda  /home/user/Obsidian-Network/crates/obs-crypto/src/data/bip39_english.txt
