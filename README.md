# Browser Passworder

A simple module for encrypting & decrypting JavaScript objects with a password in the browser.

Serializes the encrypted payload as a string of text for easy storage.

Uses browser native crypto to be the lightest possible module you can have, with the most vetted internals you could ask for (the real guts here are implemented by the browser provider).

## Installation

You need to have Node.js installed.

```bash
yarn install @metamask/browser-passworder
```

## Usage

```javascript
const { strict: assert } = require('assert');
const passworder = require('browser-passworder');

const secrets = { coolStuff: 'all', ssn: 'livin large' };
const password = 'hunter55';

passworder
  .encrypt(password, secrets)
  .then(function (blob) {
    return passworder.decrypt(password, blob);
  })
  .then(function (result) {
    assert.deepEqual(result, secrets);
  });
```

There are also some more advanced internal methods you can choose to use, but that's the basic version of it.

The most advanced alternate usage would be if you want to cache the password-derived key to speed up performance for many encryptions/decryptions with the same password.

## Details

The serialized text is stored as a JSON blob that includes two base64-encoded fields, `data` and `iv`, neither of which you need to worry about.

The data is encrypted using the `AES-GCM` algorithm. It is salted with the result of `crypto.getRandomValues()`, and the encryption vector is generated the same way.

## Contributing

### Setup

- Install [Node.js](https://nodejs.org) version 12
  - If you are using [nvm](https://github.com/creationix/nvm#installation) (recommended) running `nvm use` will automatically choose the right node version for you.
- Install [Yarn v1](https://yarnpkg.com/en/docs/install)
- Run `yarn setup` to install dependencies and run any requried post-install scripts
  - **Warning:** Do not use the `yarn` / `yarn install` command directly. Use `yarn setup` instead. The normal install command will skip required post-install scripts, leaving your development environment in an invalid state.

### Testing and Linting

Run `yarn test` to run the tests once.

Run `yarn lint` to run the linter, or run `yarn lint:fix` to run the linter and fix any automatically fixable issues.
