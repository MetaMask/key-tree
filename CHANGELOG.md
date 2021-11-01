# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0]
### Uncategorized
- Add release automation, standardize GitHub Action workflows ([#27](https://github.com/MetaMask/key-tree/pull/27))
- Migrate to jest, refactor file structure ([#26](https://github.com/MetaMask/key-tree/pull/26))
- Add basic repository standardization ([#24](https://github.com/MetaMask/key-tree/pull/24))
- Bump path-parse from 1.0.6 to 1.0.7 ([#22](https://github.com/MetaMask/key-tree/pull/22))
- Bump glob-parent from 5.1.1 to 5.1.2 ([#21](https://github.com/MetaMask/key-tree/pull/21))
- Bump hosted-git-info from 2.8.8 to 2.8.9 ([#19](https://github.com/MetaMask/key-tree/pull/19))
- Bump elliptic from 6.5.3 to 6.5.4 ([#18](https://github.com/MetaMask/key-tree/pull/18))

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

[Unreleased]: https://github.com/MetaMask/key-tree/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/MetaMask/key-tree/compare/v2.0.1...v3.0.0
[2.0.1]: https://github.com/MetaMask/key-tree/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/MetaMask/key-tree/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/MetaMask/key-tree/releases/tag/v1.0.0
