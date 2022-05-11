# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0]
### Added
- **NOTE:** This version is a significant rewrite of this package, and virtually all existing usage will break upon migrating from a previous major version.
  All pre-existing functionality is supported through different means, and various new features have been added.
- Add extended public (`xpub`) and private (`xprv`) keys ([#58](https://github.com/MetaMask/key-tree/pull/58))
- Add support for public key derivation ([#56](https://github.com/MetaMask/key-tree/pull/56))
- Add support for non-secp256k1 curves via `SLIP10Node` class ([#43](https://github.com/MetaMask/key-tree/pull/43), [#37](https://github.com/MetaMask/key-tree/pull/37), [#53](https://github.com/MetaMask/key-tree/pull/53))
  - Add support for ed25519 curve.
  - With this and other changes in this release, this package offers full [SLIP-10](https://github.com/satoshilabs/slips/blob/133ea52a8e43d338b98be208907e144277e44c0e/slip-0010.md) support for all curves except nist256p1.
  - These changes were made possible using the `@noble/*` suite of cryptography packages.
- Add extended key to BIP-44 coin type node ([#59](https://github.com/MetaMask/key-tree/pull/59))
- Add convenience methods to get public keys and addresses ([#50](https://github.com/MetaMask/key-tree/pull/50))
- Enable deriving hardened `change` and `address_index` using `BIP44CoinTypeNode` ([#37](https://github.com/MetaMask/key-tree/pull/37))

### Changed
- **BREAKING:** Change key representation format ([#58](https://github.com/MetaMask/key-tree/pull/58), [#54](https://github.com/MetaMask/key-tree/pull/54))
  - Encode string keys in hexadecimal instead of Base64.
  - Always return a `SLIP10Node` (or child class) object from derivation functions.
- **BREAKING:** Separate private keys and chain code into separate fields ([#54](https://github.com/MetaMask/key-tree/pull/54))
- **BREAKING:** Use named arguments instead of positional arguments in various functions ([#56](https://github.com/MetaMask/key-tree/pull/56))
- **BREAKING:** Make all derivation functions async ([#43](https://github.com/MetaMask/key-tree/pull/43), [#54](https://github.com/MetaMask/key-tree/pull/54))
  - All key derivation functions are now async, and node objects are initialized via a static, async `.from(...)` method. This is because some cryptographic dependencies are async.
- Update documentation to match new implementation ([#60](https://github.com/MetaMask/key-tree/pull/60), [#49](https://github.com/MetaMask/key-tree/pull/49))

### Fixed
- Remove obsolete Jest snapshots ([#41](https://github.com/MetaMask/key-tree/pull/41))
- Replace node symbol with private field ([#42](https://github.com/MetaMask/key-tree/pull/42))

## [3.0.1]
### Changed
- Update cryptography dependencies ([#29](https://github.com/MetaMask/key-tree/pull/29), [#30](https://github.com/MetaMask/key-tree/pull/30), [#31](https://github.com/MetaMask/key-tree/pull/31))
  - This results in an overall ~4x speedup in Node.js for operations with this package. Browser performance gains, if any, are not known at this time.
  - Individual pull requests:
    - `bip39@3.0.4` ([#29](https://github.com/MetaMask/key-tree/pull/29))
    - `secp256k1@4.0.2` ([#30](https://github.com/MetaMask/key-tree/pull/30))
    - `keccak@3.0.2` ([#31](https://github.com/MetaMask/key-tree/pull/31))

## [3.0.0]
### Changed
- **BREAKING:** Refactor package API ([#25](https://github.com/MetaMask/key-tree/pull/25))
  - The new API is designed to make it harder to derive incorrect keys.
  - The previous exports of this package can no longer be accessed from the main entry file.
  - For the new API, please see [the README](https://github.com/MetaMask/key-tree/blob/1743ef1bb2ca4603c6e2861b975bf2b4d60a0dbc/README.md).
- **BREAKING:** Bump minimum Node.js version to >=12.0.0 ([#20](https://github.com/MetaMask/key-tree/pull/20))

### Security
- Add reference implementation tests ([#25](https://github.com/MetaMask/key-tree/pull/25))
  - The key derivation of this package is now tested against the BIP-32 specification and [`ethereumjs-wallet`](https://github.com/ethereumjs/ethereumjs-wallet) and [`@metamask/eth-hd-keyring`](https://github.com/MetaMask/eth-hd-keyring).
  - The key derivation was found to be sound.

## [2.0.1] - 2021-02-27
### Fixed
- Correctly type `deriveKeyFromPath` `parentKey` param as optional ([#14](https://github.com/MetaMask/key-tree/pull/14))
- Only accept lowercase BIP-39 seed phrases in `deriveKeyFromPath` ([#15](https://github.com/MetaMask/key-tree/pull/15))

## [2.0.0] - 2021-02-25
### Changed
- **BREAKING:** Add input validation to `deriveKeyFromPath` ([#3](https://github.com/MetaMask/key-tree/pull/3), [#4](https://github.com/MetaMask/key-tree/pull/4))
- **BREAKING:** Change `deriveKeyFromPath` parameter order ([#3](https://github.com/MetaMask/key-tree/pull/3))
- Migrate to TypeScript, update types ([#10](https://github.com/MetaMask/key-tree/pull/10))

## [1.0.0] - 2020-09-03
### Added
- Initial release.

[Unreleased]: https://github.com/MetaMask/key-tree/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/MetaMask/key-tree/compare/v3.0.1...v4.0.0
[3.0.1]: https://github.com/MetaMask/key-tree/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/MetaMask/key-tree/compare/v2.0.1...v3.0.0
[2.0.1]: https://github.com/MetaMask/key-tree/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/MetaMask/key-tree/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/MetaMask/key-tree/releases/tag/v1.0.0
