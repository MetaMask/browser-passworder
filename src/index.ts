export type DetailedEncryptionResult = {
  vault: string;
  exportedKeyString: string;
};

export enum EncryptionResultVersion {
  V1 = '1.0',
  V2 = '2.0',
}

export type EncryptionResult = {
  data: string;
  iv: string;
  salt?: string;
  version?: EncryptionResultVersion;
};

export type DetailedDecryptResult = {
  exportedKeyString: string;
  vault: unknown;
  salt: string;
};

const EXPORT_FORMAT = 'jwk';
const DERIVED_KEY_FORMAT = 'AES-GCM';
const STRING_ENCODING = 'utf-8';
const KEY_DERIVATION_ITERATIONS = {
  [EncryptionResultVersion.V1]: 10000,
  [EncryptionResultVersion.V2]: 600000,
};

/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param password - The password to use for encryption.
 * @param dataObj - The data to encrypt.
 * @param key - The CryptoKey to encrypt with.
 * @param salt - The salt to use to encrypt.
 * @param version - The encryption version to use.
 * @returns The encrypted vault.
 */
export async function encrypt<R>(
  password: string,
  dataObj: R,
  key?: CryptoKey,
  salt: string = generateSalt(),
  version = EncryptionResultVersion.V2,
): Promise<string> {
  const cryptoKey =
    key ||
    (await keyFromPassword(password, salt, KEY_DERIVATION_ITERATIONS[version]));
  const payload = await encryptWithKey(cryptoKey, dataObj, version);
  payload.salt = salt;
  return JSON.stringify(payload);
}

/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param password - A password to use for encryption.
 * @param dataObj - The data to encrypt.
 * @param salt - The salt used to encrypt.
 * @param version - The encryption version to use.
 * @returns The vault and exported key string.
 */
export async function encryptWithDetail<R>(
  password: string,
  dataObj: R,
  salt = generateSalt(),
  version = EncryptionResultVersion.V2,
): Promise<DetailedEncryptionResult> {
  const key = await keyFromPassword(
    password,
    salt,
    KEY_DERIVATION_ITERATIONS[version],
    true,
  );
  const exportedKeyString = await exportKey(key);
  const vault = await encrypt(password, dataObj, key, salt, version);

  return {
    vault,
    exportedKeyString,
  };
}

/**
 * Encrypts the provided serializable javascript object using the
 * provided CryptoKey and returns an object containing the cypher text and
 * the initialization vector used.
 *
 * @param key - The CryptoKey to encrypt with.
 * @param dataObj - A serializable JavaScript object to encrypt.
 * @param version - The encryption version to use.
 * @returns The encrypted data.
 */
export async function encryptWithKey<R>(
  key: CryptoKey,
  dataObj: R,
  version = EncryptionResultVersion.V2,
): Promise<EncryptionResult> {
  const data = JSON.stringify(dataObj);
  const dataBuffer = Buffer.from(data, STRING_ENCODING);
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
    version,
    data: vaultStr,
    iv: vectorStr,
  };
}

/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value.
 *
 * @param password - The password to decrypt with.
 * @param text - The cypher text to decrypt.
 * @param key - The key to decrypt with.
 * @returns The decrypted data.
 */
export async function decrypt(
  password: string,
  text: string,
  key?: CryptoKey,
): Promise<unknown> {
  const payload = JSON.parse(text);
  const { salt, version } = payload;

  if (key) {
    return decryptWithKey(key, payload);
  }

  let cryptoKey: CryptoKey;
  switch (version) {
    case EncryptionResultVersion.V1:
      cryptoKey = await keyFromPassword(
        password,
        salt,
        KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V1],
      );
      break;
    case EncryptionResultVersion.V2:
      cryptoKey = await keyFromPassword(
        password,
        salt,
        KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V2],
      );
      break;
    default:
      cryptoKey = await keyFromPassword(
        password,
        salt,
        KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V1],
      );
  }

  const result = await decryptWithKey(cryptoKey, payload);
  return result;
}

/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value, keyString, and salt.
 *
 * @param password - The password to decrypt with.
 * @param text - The encrypted vault to decrypt.
 * @returns The decrypted vault along with the salt and exported key.
 */
export async function decryptWithDetail(
  password: string,
  text: string,
): Promise<DetailedDecryptResult> {
  const payload = JSON.parse(text);
  const { salt, version } = payload;
  let key: CryptoKey;
  switch (version) {
    case EncryptionResultVersion.V1:
      key = await keyFromPassword(
        password,
        salt,
        KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V1],
        true,
      );
      break;
    case EncryptionResultVersion.V2:
      key = await keyFromPassword(
        password,
        salt,
        KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V2],
        true,
      );
      break;
    default:
      key = await keyFromPassword(
        password,
        salt,
        // This ensures compatibility with data encrypted with
        // older versions, which may not even have a `version` property,
        // and for those '1.0' should be inferred.
        KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V1],
        true,
      );
  }
  const exportedKeyString = await exportKey(key);
  const vault = await decrypt(password, text, key);

  return {
    exportedKeyString,
    vault,
    salt,
  };
}

/**
 * Given a CryptoKey and an EncryptionResult object containing the initialization
 * vector (iv) and data to decrypt, return the resulting decrypted value.
 *
 * @param key - The CryptoKey to decrypt with.
 * @param payload - The payload to decrypt, returned from an encryption method.
 * @returns The decrypted data.
 */
export async function decryptWithKey<R>(
  key: CryptoKey,
  payload: EncryptionResult,
): Promise<R> {
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
    const decryptedStr = Buffer.from(decryptedData).toString(STRING_ENCODING);
    decryptedObj = JSON.parse(decryptedStr);
  } catch (e) {
    throw new Error('Incorrect password');
  }

  return decryptedObj;
}

/**
 * Receives an exported CryptoKey string and creates a key.
 *
 * @param keyString - The key string to import.
 * @returns A CryptoKey.
 */
export async function importKey(keyString: string): Promise<CryptoKey> {
  const key = await window.crypto.subtle.importKey(
    EXPORT_FORMAT,
    JSON.parse(keyString),
    DERIVED_KEY_FORMAT,
    true,
    ['encrypt', 'decrypt'],
  );

  return key;
}

/**
 * Receives an exported CryptoKey string, creates a key,
 * and decrypts cipher text with the reconstructed key.
 *
 * @param key - The CryptoKey to export.
 * @returns A key string.
 */
export async function exportKey(key: CryptoKey): Promise<string> {
  const exportedKey = await window.crypto.subtle.exportKey(EXPORT_FORMAT, key);
  return JSON.stringify(exportedKey);
}

/**
 * Generate a CryptoKey from a password and random salt.
 *
 * @param password - The password to use to generate key.
 * @param salt - The salt string to use in key derivation.
 * @param iterations - The number of iterations used to derive the key.
 * @param exportable - Should the derived key be exportable.
 * @returns A CryptoKey for encryption and decryption.
 */
export async function keyFromPassword(
  password: string,
  salt: string,
  iterations = KEY_DERIVATION_ITERATIONS[EncryptionResultVersion.V2],
  exportable = false,
): Promise<CryptoKey> {
  const passBuffer = Buffer.from(password, STRING_ENCODING);
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
      iterations,
      hash: 'SHA-256',
    },
    key,
    { name: DERIVED_KEY_FORMAT, length: 256 },
    exportable,
    ['encrypt', 'decrypt'],
  );

  return derivedKey;
}

/**
 * Converts a hex string into a buffer.
 *
 * @param str - Hex encoded string.
 * @returns The string ecoded as a byte array.
 */
export function serializeBufferFromStorage(str: string): Uint8Array {
  const stripStr = str.slice(0, 2) === '0x' ? str.slice(2) : str;
  const buf = new Uint8Array(stripStr.length / 2);
  for (let i = 0; i < stripStr.length; i += 2) {
    const seg = stripStr.substr(i, 2);
    buf[i / 2] = parseInt(seg, 16);
  }
  return buf;
}

/**
 * Converts a buffer into a hex string ready for storage.
 *
 * @param buffer - Buffer to serialize.
 * @returns A hex encoded string.
 */
export function serializeBufferForStorage(buffer: Uint8Array): string {
  let result = '0x';
  buffer.forEach((value) => {
    result += unprefixedHex(value);
  });
  return result;
}

/**
 * Converts a number into hex value, and ensures proper leading 0
 * for single characters strings.
 *
 * @param num - The number to convert to string.
 * @returns An unprefixed hex string.
 */
function unprefixedHex(num: number): string {
  let hex = num.toString(16);
  while (hex.length < 2) {
    hex = `0${hex}`;
  }
  return hex;
}

/**
 * Generates a random string for use as a salt in CryptoKey generation.
 *
 * @param byteCount - The number of bytes to generate.
 * @returns A randomly generated string.
 */
export function generateSalt(byteCount = 32): string {
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
