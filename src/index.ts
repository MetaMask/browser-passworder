export type DetailedEncryptionResult = {
  vault: string;
  exportedKeyString: string;
};

export type PBKDF2Params = {
  iterations: number;
};

export type KeyDerivationOptions = {
  algorithm: 'PBKDF2';
  params: PBKDF2Params;
};

export type EncryptionKey = {
  key: CryptoKey;
  derivationOptions: KeyDerivationOptions;
};

export type ExportedEncryptionKey = {
  key: JsonWebKey;
  derivationOptions: KeyDerivationOptions;
};

export type EncryptionResult = {
  data: string;
  iv: string;
  salt?: string;
  // old encryption results will not have this
  keyMetadata?: KeyDerivationOptions;
};

export type DetailedDecryptResult = {
  exportedKeyString: string;
  vault: unknown;
  salt: string;
};

const EXPORT_FORMAT = 'jwk';
const DERIVED_KEY_FORMAT = 'AES-GCM';
const STRING_ENCODING = 'utf-8';
const OLD_DERIVATION_PARAMS: KeyDerivationOptions = {
  algorithm: 'PBKDF2',
  params: {
    iterations: 10_000,
  },
};
const DEFAULT_DERIVATION_PARAMS: KeyDerivationOptions = {
  algorithm: 'PBKDF2',
  params: {
    iterations: 900_000,
  },
};

/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param password - The password to use for encryption.
 * @param dataObj - The data to encrypt.
 * @param key - The CryptoKey to encrypt with.
 * @param salt - The salt to use to encrypt.
 * @param keyDerivationOptions - The options to use for key derivation.
 * @returns The encrypted vault.
 */
export async function encrypt<R>(
  password: string,
  dataObj: R,
  key?: EncryptionKey | CryptoKey,
  salt: string = generateSalt(),
  keyDerivationOptions = DEFAULT_DERIVATION_PARAMS,
): Promise<string> {
  const cryptoKey =
    key || (await keyFromPassword(password, salt, false, keyDerivationOptions));
  const payload = await encryptWithKey(cryptoKey, dataObj);
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
 * @param keyDerivationOptions - The options to use for key derivation.
 * @returns The vault and exported key string.
 */
export async function encryptWithDetail<R>(
  password: string,
  dataObj: R,
  salt = generateSalt(),
  keyDerivationOptions = DEFAULT_DERIVATION_PARAMS,
): Promise<DetailedEncryptionResult> {
  const key = await keyFromPassword(password, salt, true, keyDerivationOptions);
  const exportedKeyString = await exportKey(key);
  const vault = await encrypt(password, dataObj, key, salt);

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
 * @param encryptionKey - The CryptoKey to encrypt with.
 * @param dataObj - A serializable JavaScript object to encrypt.
 * @returns The encrypted data.
 */
export async function encryptWithKey<R>(
  encryptionKey: EncryptionKey | CryptoKey,
  dataObj: R,
): Promise<EncryptionResult> {
  const data = JSON.stringify(dataObj);
  const dataBuffer = Buffer.from(data, STRING_ENCODING);
  const vector = global.crypto.getRandomValues(new Uint8Array(16));
  const key = unwrapKey(encryptionKey);

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
  const encryptionResult: EncryptionResult = {
    data: vaultStr,
    iv: vectorStr,
  };

  if (isEncryptionKey(encryptionKey)) {
    encryptionResult.keyMetadata = encryptionKey.derivationOptions;
  }

  return encryptionResult;
}

/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value.
 *
 * @param password - The password to decrypt with.
 * @param text - The cypher text to decrypt.
 * @param encryptionKey - The key to decrypt with.
 * @returns The decrypted data.
 */
export async function decrypt(
  password: string,
  text: string,
  encryptionKey?: EncryptionKey | CryptoKey,
): Promise<unknown> {
  const payload = JSON.parse(text);
  const { salt, keyMetadata } = payload;
  const cryptoKey = unwrapKey(
    encryptionKey ||
      (await keyFromPassword(password, salt, false, keyMetadata)),
  );

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
  const { salt, keyMetadata } = payload;
  const key = await keyFromPassword(password, salt, true, keyMetadata);
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
 * @param encryptionKey - The CryptoKey to decrypt with.
 * @param payload - The payload to decrypt, returned from an encryption method.
 * @returns The decrypted data.
 */
export async function decryptWithKey<R>(
  encryptionKey: EncryptionKey | CryptoKey,
  payload: EncryptionResult,
): Promise<R> {
  const encryptedData = Buffer.from(payload.data, 'base64');
  const vector = Buffer.from(payload.iv, 'base64');
  const key = unwrapKey(encryptionKey);

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
 * @returns An EncryptionKey.
 */
export async function importKey(
  keyString: string,
): Promise<EncryptionKey | CryptoKey> {
  const exportedEncryptionKey = JSON.parse(keyString);

  if (isExportedEncryptionKey(exportedEncryptionKey)) {
    return {
      key: await window.crypto.subtle.importKey(
        EXPORT_FORMAT,
        exportedEncryptionKey.key,
        DERIVED_KEY_FORMAT,
        true,
        ['encrypt', 'decrypt'],
      ),
      derivationOptions: exportedEncryptionKey.derivationOptions,
    };
  }

  return await window.crypto.subtle.importKey(
    EXPORT_FORMAT,
    exportedEncryptionKey,
    DERIVED_KEY_FORMAT,
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Receives an exported CryptoKey string, creates a key,
 * and decrypts cipher text with the reconstructed key.
 *
 * @param encryptionKey - The CryptoKey to export.
 * @returns A key string.
 */
export async function exportKey(
  encryptionKey: CryptoKey | EncryptionKey,
): Promise<string> {
  if (isEncryptionKey(encryptionKey)) {
    return JSON.stringify({
      key: await window.crypto.subtle.exportKey(
        EXPORT_FORMAT,
        encryptionKey.key,
      ),
      derivationOptions: encryptionKey.derivationOptions,
    });
  }

  return JSON.stringify(
    await window.crypto.subtle.exportKey(EXPORT_FORMAT, encryptionKey),
  );
}

/**
 * Generate a CryptoKey from a password and random salt.
 *
 * @param password - The password to use to generate key.
 * @param salt - The salt string to use in key derivation.
 * @param exportable - Whether or not the key should be exportable.
 * @returns A CryptoKey for encryption and decryption.
 */
export async function keyFromPassword(
  password: string,
  salt: string,
  exportable?: boolean,
): Promise<CryptoKey>;
/**
 * Generate a CryptoKey from a password and random salt, specifying
 * key derivation options.
 *
 * @param password - The password to use to generate key.
 * @param salt - The salt string to use in key derivation.
 * @param exportable - Whether or not the key should be exportable.
 * @param opts - The options to use for key derivation.
 * @returns An EncryptionKey for encryption and decryption.
 */
export async function keyFromPassword(
  password: string,
  salt: string,
  exportable?: boolean,
  opts?: KeyDerivationOptions,
): Promise<EncryptionKey>;
// The overloads are already documented.
// eslint-disable-next-line jsdoc/require-jsdoc
export async function keyFromPassword(
  password: string,
  salt: string,
  exportable = false,
  opts: KeyDerivationOptions = OLD_DERIVATION_PARAMS,
): Promise<CryptoKey | EncryptionKey> {
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
      iterations: opts.params.iterations,
      hash: 'SHA-256',
    },
    key,
    { name: DERIVED_KEY_FORMAT, length: 256 },
    exportable,
    ['encrypt', 'decrypt'],
  );

  return opts
    ? {
        key: derivedKey,
        derivationOptions: opts,
      }
    : derivedKey;
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

/**
 * Checks if the provided key is an `EncryptionKey`.
 *
 * @param encryptionKey - The object to check.
 * @returns Whether or not the key is an `EncryptionKey`.
 */
export function isEncryptionKey(
  encryptionKey: unknown,
): encryptionKey is EncryptionKey {
  return (
    encryptionKey !== null &&
    typeof encryptionKey === 'object' &&
    'key' in encryptionKey &&
    'derivationOptions' in encryptionKey &&
    encryptionKey.key instanceof CryptoKey &&
    isKeyDerivationOptions(encryptionKey.derivationOptions)
  );
}

/**
 * Checks if the provided object is a `KeyDerivationOptions`.
 *
 * @param derivationOptions - The object to check.
 * @returns Whether or not the object is a `KeyDerivationOptions`.
 */
export function isKeyDerivationOptions(
  derivationOptions: unknown,
): derivationOptions is KeyDerivationOptions {
  return (
    derivationOptions !== null &&
    typeof derivationOptions === 'object' &&
    'algorithm' in derivationOptions &&
    'params' in derivationOptions
  );
}

/**
 * Checks if the provided key is an `ExportedEncryptionKey`.
 *
 * @param exportedKey - The object to check.
 * @returns Whether or not the object is an `ExportedEncryptionKey`.
 */
export function isExportedEncryptionKey(
  exportedKey: unknown,
): exportedKey is ExportedEncryptionKey {
  return (
    exportedKey !== null &&
    typeof exportedKey === 'object' &&
    'key' in exportedKey &&
    'derivationOptions' in exportedKey &&
    isKeyDerivationOptions(exportedKey.derivationOptions)
  );
}

/**
 * Returns the `CryptoKey` from the provided encryption key.
 * If the provided key is a `CryptoKey`, it is returned as is.
 *
 * @param encryptionKey - The key to unwrap.
 * @returns The `CryptoKey` from the provided encryption key.
 */
export function unwrapKey(encryptionKey: EncryptionKey | CryptoKey): CryptoKey {
  return isEncryptionKey(encryptionKey) ? encryptionKey.key : encryptionKey;
}
