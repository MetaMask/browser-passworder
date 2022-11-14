# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/MetaMask/browser-passworder/compare/v4.0.2...HEAD
[4.0.2]: https://github.com/MetaMask/browser-passworder/compare/v4.0.1...v4.0.2
[4.0.1]: https://github.com/MetaMask/browser-passworder/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/MetaMask/browser-passworder/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/MetaMask/browser-passworder/releases/tag/v3.0.0
