import * as Unibabel from 'browserify-unibabel'

interface EncryptionResult {
  data: string,
  iv: string,
  salt?: string,
}

/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 * 
 * @param {string} password - password to use for encryption
 * @param {R} dataObj - data to encrypt
 * @returns {Promise<string>} cypher text
 */
function encrypt <R>(password: string, dataObj: R): Promise<string> {
  var salt = generateSalt()

  return keyFromPassword(password, salt)
  .then(function (passwordDerivedKey) {
    return encryptWithKey(passwordDerivedKey, dataObj)
  })
  .then(function (payload) {
    payload.salt = salt
    return JSON.stringify(payload)
  })
}

/**
 * Encrypts the provided serializable javascript object using the
 * provided CryptoKey and returns an object containing the cypher text and
 * the initialization vector used.
 * @param {CryptoKey} key - CryptoKey to encrypt with 
 * @param {R} dataObj - Serializable javascript object to encrypt
 * @returns {EncryptionResult}
 */
function encryptWithKey <R>(key: CryptoKey, dataObj: R): Promise<EncryptionResult> {
  var data = JSON.stringify(dataObj)
  var dataBuffer = Unibabel.utf8ToBuffer(data)
  var vector = global.crypto.getRandomValues(new Uint8Array(16))
  return global.crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: vector,
  }, key, dataBuffer).then(function (buf) {
    var buffer = new Uint8Array(buf)
    var vectorStr = Unibabel.bufferToBase64(vector)
    var vaultStr = Unibabel.bufferToBase64(buffer)
    return {
      data: vaultStr,
      iv: vectorStr,
    }
  })
}

/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value
 * @param {string} password - password to decrypt with
 * @param {string} text - cypher text to decrypt
 */
function decrypt <R>(password: string, text: string): Promise<R> {
  const payload = JSON.parse(text)
  const salt = payload.salt
  return keyFromPassword(password, salt)
  .then(function (key) {
    return decryptWithKey(key, payload)
  })
}

/**
 * Given a CryptoKey and an EncryptionResult object containing the initialization
 * vector (iv) and data to decrypt, return the resulting decrypted value.
 * @param {CryptoKey} key - CryptoKey to decrypt with
 * @param {EncryptionResult} payload - payload returned from an encryption method
 */
function decryptWithKey<R>(key: CryptoKey, payload: EncryptionResult): Promise<R> {
  const encryptedData = Unibabel.base64ToBuffer(payload.data)
  const vector = Unibabel.base64ToBuffer(payload.iv)
  return crypto.subtle.decrypt({name: 'AES-GCM', iv: vector}, key, encryptedData)
  .then(function (result) {
    const decryptedData = new Uint8Array(result)
    const decryptedStr = Unibabel.bufferToUtf8(decryptedData)
    const decryptedObj = JSON.parse(decryptedStr)
    return decryptedObj
  })
  .catch(function (reason) {
    throw new Error('Incorrect password')
  })
}

/**
 * Generate a CryptoKey from a password and random salt
 * @param {string} password - The password to use to generate key
 * @param {string} salt - The salt string to use in key derivation
 */
function keyFromPassword (password: string, salt: string): Promise<CryptoKey> {
  var passBuffer = Unibabel.utf8ToBuffer(password)
  var saltBuffer = Unibabel.base64ToBuffer(salt)

  return global.crypto.subtle.importKey(
    'raw',
    passBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  ).then(function (key) {

    return global.crypto.subtle.deriveKey(
      { name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 10000,
        hash: 'SHA-256',
      },
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  })
}

/**
 * Converts a hex string into a buffer.
 * @param {string} str - hex encoded string
 * @returns {Uint8Array}
 */
function serializeBufferFromStorage (str: string): Uint8Array {
  var stripStr = (str.slice(0, 2) === '0x') ? str.slice(2) : str
  var buf = new Uint8Array(stripStr.length / 2)
  for (var i = 0; i < stripStr.length; i += 2) {
    var seg = stripStr.substr(i, 2)
    buf[i / 2] = parseInt(seg, 16)
  }
  return buf
}

/**
 * Converts a buffer into a hex string ready for storage
 * @param {Uint8Array} buffer - Buffer to serialize
 * @returns {string} hex encoded string
 */
function serializeBufferForStorage (buffer: Uint8Array): string {
  var result = '0x'
  var len = buffer.length || buffer.byteLength
  for (var i = 0; i < len; i++) {
    result += unprefixedHex(buffer[i])
  }
  return result
}

/**
 * Converts a number into hex value, and ensures proper leading 0
 * for single characters strings.
 * @param {number} num - number to convert to string
 * @returns {string} hex string
 */
function unprefixedHex (num: number): string {
  var hex = num.toString(16)
  while (hex.length < 2) {
    hex = '0' + hex
  }
  return hex
}

/**
 * Generates a random string for use as a salt in CryptoKey generation
 * @param {number} byteCount - Number of bytes to generate
 * @returns {string} randomly generated string 
 */
function generateSalt (byteCount: number = 32): string {
  var view = new Uint8Array(byteCount)
  global.crypto.getRandomValues(view)
  // Uint8Array is a fixed length array and thus does not have methods like pop, etc
  // so TypeScript complains about casting it to an array. Array.from() works here for
  // getting the proper type, but it results in a functional difference. In order to
  // cast, you have to first cast view to unknown then cast the unknown value to number[]
  // TypeScript ftw: double opt in to write potentially type-mismatched code. 
  var b64encoded = btoa(String.fromCharCode.apply(null, (view as unknown) as number[]))
  return b64encoded
}

export = {

  // Simple encryption methods:
  encrypt,
  decrypt,

  // More advanced encryption methods:
  keyFromPassword,
  encryptWithKey,
  decryptWithKey,

  // Buffer <-> Hex string methods
  serializeBufferForStorage,
  serializeBufferFromStorage,

  generateSalt,
}