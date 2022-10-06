interface EncryptionResult {
  data: string;
  iv: string;
  salt?: string;
}

interface DecryptResult {
  extractedKeyString: string;
  vault: object;
  data: string;
}

const EXPORT_FORMAT = 'jwk';
const DERIVED_KEY_FORMAT = 'AES-GCM';

/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param {string} password - password to use for encryption
 * @param {R} dataObj - data to encrypt
 * @returns {Promise<string>} cypher text
 */
async function encrypt<R>(password: string, dataObj: R): Promise<string> {
  const salt = generateSalt();

  const passwordDerivedKey = await keyFromPassword(password, salt);
  const payload = await encryptWithKey(passwordDerivedKey, dataObj);
  payload.salt = salt;

  return JSON.stringify(payload);
}

/**
 * Encrypts the provided serializable javascript object using the
 * provided CryptoKey and returns an object containing the cypher text and
 * the initialization vector used.
 * @param {CryptoKey} key - CryptoKey to encrypt with
 * @param {R} dataObj - Serializable javascript object to encrypt
 * @returns {EncryptionResult}
 */
async function encryptWithKey<R>(
  key: CryptoKey,
  dataObj: R,
): Promise<EncryptionResult> {
  const data = JSON.stringify(dataObj);
  const dataBuffer = Buffer.from(data, 'utf-8');
  const vector = global.crypto.getRandomValues(new Uint8Array(16));

  const buf = await global.crypto.subtle.encrypt(
    {
      name: DERIVED_KEY_FORMAT,
      iv: vector,
    },
    key,
    dataBuffer,
  );

  const buffer = new Uint8Array(buf);
  const vectorStr = Buffer.from(vector).toString('base64');
  const vaultStr = Buffer.from(buffer).toString('base64');
  return {
    data: vaultStr,
    iv: vectorStr,
  };
}

/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value
 * @param {string} password - password to decrypt with
 * @param {string} text - cypher text to decrypt
 */
async function decrypt<R>(
  password: string,
  text: string,
): Promise<DecryptResult> {
  const payload = JSON.parse(text);
  const { salt } = payload;
  const key = await keyFromPassword(password, salt);

  const extractedKeyString = await exportKey(key);
  const vault = await decryptWithKey(key, payload);
  const data = JSON.stringify(payload);

  return {
    extractedKeyString,
    vault,
    data,
  };
}

async function decryptWithEncryptedKeyString(keyString: string, data: string) {
  const key = await createKeyFromString(keyString);

  return await decryptWithKey(key, JSON.parse(data));
}

async function createKeyFromString(keyString: string): Promise<CryptoKey> {
  const key = await window.crypto.subtle.importKey(
    EXPORT_FORMAT,
    JSON.parse(keyString),
    DERIVED_KEY_FORMAT,
    true,
    ['encrypt', 'decrypt'],
  );

  return key;
}

async function exportKey(key: CryptoKey): Promise<string> {
  const exportedKey = window.crypto.subtle.exportKey(EXPORT_FORMAT, key);
  return JSON.stringify(exportedKey);
}

/**
 * Given a CryptoKey and an EncryptionResult object containing the initialization
 * vector (iv) and data to decrypt, return the resulting decrypted value.
 * @param {CryptoKey} key - CryptoKey to decrypt with
 * @param {EncryptionResult} payload - payload returned from an encryption method
 */
async function decryptWithKey<R>(
  key: CryptoKey,
  payload: EncryptionResult,
): Promise<object> {
  const encryptedData = Buffer.from(payload.data, 'base64');
  const vector = Buffer.from(payload.iv, 'base64');

  let decryptedObj;
  try {
    const result = await crypto.subtle.decrypt(
      { name: DERIVED_KEY_FORMAT, iv: vector },
      key,
      encryptedData,
    );

    const decryptedData = new Uint8Array(result);
    const decryptedStr = Buffer.from(decryptedData).toString('utf-8');
    decryptedObj = JSON.parse(decryptedStr);
  } catch (e) {
    throw new Error('Incorrect password');
  }

  return decryptedObj;
}

/**
 * Generate a CryptoKey from a password and random salt
 * @param {string} password - The password to use to generate key
 * @param {string} salt - The salt string to use in key derivation
 */
async function keyFromPassword(
  password: string,
  salt: string,
): Promise<CryptoKey> {
  const passBuffer = Buffer.from(password, 'utf-8');
  const saltBuffer = Buffer.from(salt, 'base64');

  const key = await global.crypto.subtle.importKey(
    'raw',
    passBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey'],
  );

  const derivedKey = await global.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 10000,
      hash: 'SHA-256',
    },
    key,
    { name: DERIVED_KEY_FORMAT, length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  return derivedKey;
}

/**
 * Converts a hex string into a buffer.
 * @param {string} str - hex encoded string
 * @returns {Uint8Array}
 */
function serializeBufferFromStorage(str: string): Uint8Array {
  const stripStr = str.slice(0, 2) === '0x' ? str.slice(2) : str;
  const buf = new Uint8Array(stripStr.length / 2);
  for (let i = 0; i < stripStr.length; i += 2) {
    const seg = stripStr.substr(i, 2);
    buf[i / 2] = parseInt(seg, 16);
  }
  return buf;
}

/**
 * Converts a buffer into a hex string ready for storage
 * @param {Uint8Array} buffer - Buffer to serialize
 * @returns {string} hex encoded string
 */
function serializeBufferForStorage(buffer: Uint8Array): string {
  let result = '0x';
  const len = buffer.length || buffer.byteLength;
  for (let i = 0; i < len; i++) {
    result += unprefixedHex(buffer[i]);
  }
  return result;
}

/**
 * Converts a number into hex value, and ensures proper leading 0
 * for single characters strings.
 * @param {number} num - number to convert to string
 * @returns {string} hex string
 */
function unprefixedHex(num: number): string {
  let hex = num.toString(16);
  while (hex.length < 2) {
    hex = `0${hex}`;
  }
  return hex;
}

/**
 * Generates a random string for use as a salt in CryptoKey generation
 * @param {number} byteCount - Number of bytes to generate
 * @returns {string} randomly generated string
 */
function generateSalt(byteCount = 32): string {
  const view = new Uint8Array(byteCount);
  global.crypto.getRandomValues(view);
  // Uint8Array is a fixed length array and thus does not have methods like pop, etc
  // so TypeScript complains about casting it to an array. Array.from() works here for
  // getting the proper type, but it results in a functional difference. In order to
  // cast, you have to first cast view to unknown then cast the unknown value to number[]
  // TypeScript ftw: double opt in to write potentially type-mismatched code.
  const b64encoded = btoa(
    String.fromCharCode.apply(null, view as unknown as number[]),
  );
  return b64encoded;
}

export = {
  // Simple encryption methods:
  encrypt,
  decrypt,

  // More advanced encryption methods:
  keyFromPassword,
  encryptWithKey,
  decryptWithKey,
  createKeyFromString,
  decryptWithEncryptedKeyString,

  // Buffer <-> Hex string methods
  serializeBufferForStorage,
  serializeBufferFromStorage,

  generateSalt,
};
