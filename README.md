# Browser Passworder

A simple module for encrypting & decrypting Javascript objects with a password in the browser.

Serializes the encrypted payload into a string of text


## Installation

You need to have node.js installed.

```bash
npm install browser-passworder
```

## Usage

```javascript
var passworder = require('browser-passworder')

var secrets = { coolStuff: 'all', ssn: 'livin large' }
var password = 'hunter55'

passworder.encrypt(password, secrets)
.then(function(blob) {
  return passworder.decrypt(password, blob)
})
.then(function(result) {
  assert.deepEqual(result, secrets)
})
```

There are also some more advanced internal methods you can choose to use, but that's the basic version of it.

The most advanced alternate usage would be if you want to cache the password-derived key to speed up performance for many encryptions/decryptions with the same password.

## Details

The serialized text is stored as a JSON blob that includes two base64-encoded fields, `data` and `iv`, neither of which you need to worry about.

## Running Tests

```bash
npm test
```
