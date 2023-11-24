# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.3.0]
### Added
- Added `isVaultUpdated` function to verify if a given vault was encrypted with the target encryption parameters. ([#53](https://github.com/MetaMask/browser-passworder/pull/53))
- Added optional `targetDerivationParams` argument to `updateVault` and `updateVaultWithDetail`. ([#55](https://github.com/MetaMask/browser-passworder/pull/55))
  - This argument allows to specify the desired parameters to use

## [4.2.0]
### Added
- Support key derivation options ([#49](https://github.com/MetaMask/browser-passworder/pull/49))
  - Added `EncryptionKey` type to hold a `CryptoKey` along with its derivation parameters.
  - Added `ExportedEncryptionKey` type to hold a `JsonWebKey` along with its derivation parameters.
  - Added Optional `keyMetadata` property of type `KeyDerivationOptions` to `EncryptionResult`.
  - Added Optional `opts`  argument to `keyFromPassword` to specify algorithm and parameters to be used in the key derivation. Defaults to `PBKDF2` with 900.000 iterations.(https://github.com/MetaMask/browser-passworder/pull/49))
  - Added `iterations` argument to `keyFromPassword` function.
  - Added optional `keyDerivationOptions` argument to `encrypt` and `encryptWithDetail` to specify algorithm and parameters to be used in the key Defaults to `PBKDF2` at 900.000 iterations.
- Added `updateVaultWithDetail` function to update existing vault and exported key with a safer encryption method if available ([#49](https://github.com/MetaMask/browser-passworder/pull/49))
- Added `updateVault` function to update existing vault string with a safer encryption method if available ([#49](https://github.com/MetaMask/browser-passworder/pull/49))

### Changed
- Add optional parameters and properties to support custom derivation options ([#49](https://github.com/MetaMask/browser-passworder/pull/49))
  - `encrypt` method accepts both `EncryptionKey` and `CryptoKey` types as `key` argument.
  - `encryptWithKey` method accepts both `EncryptionKey` and `CryptoKey` types as `key` argument.
  - `decrypt` method accepts both `EncryptionKey` and `CryptoKey` types as `key` argument.
  - `decryptWithKey` method accepts both `EncryptionKey` and `CryptoKey` types as `key` argument.
  - `importKey` method returns a `CryptoKey` when a JWK string is passed, or an `EncryptionKey` when an `ExportedEncryptionKey` string is passed.
  - `exportKey` method accepts both `EncryptionKey` and `CryptoKey` types as `key` argument, and returns an `ExportedEncryptionKey` for the former and a `JsonWebKey` for the latter.
- Pin TypeScript version to `~4.8.4` ([#50](https://github.com/MetaMask/browser-passworder/pull/50))

## [4.1.0]
### Changed
- Export data types ([#45](https://github.com/MetaMask/browser-passworder/pull/45))
  - This module now exports the following date types: `DetailedEncryptionResult`, `DetailedDecryptResult`, and `EncryptionResult`

## [4.0.2]
### Fixed
- Restore derived key default exportable to `false`, provide option to make exportable ([#38](https://github.com/MetaMask/browser-passworder/pull/38))
  - `keyFromPassword` will now default to generating a non-exportable key, just as it had prior to v4.
  - This removes an unintended breaking change from v4

## [4.0.1]
### Fixed
- Fix publishing script ([#35](https://github.com/MetaMask/browser-passworder/pull/35))
  - No functional changes from v4.0.0. This just makes it possible to publish to npm again. v4.0.0 was not published.

## [4.0.0]
### Added
- Allow decrypting and encrypting with exported and imported keys ([#29](https://github.com/MetaMask/browser-passworder/pull/29))

### Changed
- **BREAKING**: Set minimum Node.js version to v14 ([#24](https://github.com/MetaMask/browser-passworder/pull/24))

## [3.0.0]
### Added
- Add LICENSE file ([#1](https://github.com/MetaMask/browser-passworder/pull/1))
  - Previous versions were listed as being licensed as ISC, but the file was missing.

### Changed
- **BREAKING**: Rename package from `browser-passworder` to `@metamask/browser-passworder` ([#14](https://github.com/MetaMask/browser-passworder/pull/14))
- **BREAKING**: Set minimum Node.js version to v12 ([#9](https://github.com/MetaMask/browser-passworder/pull/9))
- Convert to TypeScript ([#6](https://github.com/MetaMask/browser-passworder/pull/6))
- Remove `browserify-unibabel` dependency ([#13](https://github.com/MetaMask/browser-passworder/pull/13))

[Unreleased]: https://github.com/MetaMask/browser-passworder/compare/v4.3.0...HEAD
[4.3.0]: https://github.com/MetaMask/browser-passworder/compare/v4.2.0...v4.3.0
[4.2.0]: https://github.com/MetaMask/browser-passworder/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/MetaMask/browser-passworder/compare/v4.0.2...v4.1.0
[4.0.2]: https://github.com/MetaMask/browser-passworder/compare/v4.0.1...v4.0.2
[4.0.1]: https://github.com/MetaMask/browser-passworder/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/MetaMask/browser-passworder/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/MetaMask/browser-passworder/releases/tag/v3.0.0
