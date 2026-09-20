import { hasProperty, isPlainObject } from '@metamask/utils';

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

// Bounds applied to key-derivation options before they reach WebCrypto.
// A vault is attacker-controllable input: without a lower bound a crafted
// vault silently weakens the KDF, and without an upper bound a huge
// iteration count exhausts the CPU on every unlock attempt. The ceiling is
// a small multiple of the legitimate default (900,000): nothing genuine
// needs more, and higher values turn a substituted vault into a UI freeze.
const MIN_PBKDF2_ITERATIONS = 1_000;
const MAX_PBKDF2_ITERATIONS = 3_000_000;

// Minimum accepted salt length in bytes (128 bits). Shorter salts do not
// provide enough entropy to guarantee per-vault KDF uniqueness.
const MIN_SALT_BYTE_LENGTH = 16;

/**
 * Validates key-derivation options, whether they come from an untrusted
 * vault or from a direct API call.
 *
 * @param opts - The key derivation options to validate.
 * @throws If the options are malformed or out of bounds.
 */
function validateKeyDerivationOptions(opts: KeyDerivationOptions): void {
  if (!isKeyDerivationOptions(opts)) {
    throw new Error('Invalid key derivation options');
  }
  if (opts.algorithm !== 'PBKDF2') {
    throw new Error(`Unsupported key derivation algorithm: ${opts.algorithm}`);
  }
  const { iterations } = opts.params;
  if (
    !Number.isSafeInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw new Error(
      `Invalid PBKDF2 iteration count: must be an integer between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}`,
    );
  }
}

/**
 * Parses an untrusted vault string and validates its required fields.
 * A raw `JSON.parse` error or a vault missing `data`, `iv`, or `salt`
 * surfaces here as a single typed "invalid vault format" error instead of
 * an unhandled `SyntaxError`/`TypeError` deeper in the decrypt path.
 *
 * @param text - The vault string to parse.
 * @returns The validated vault payload.
 */
function parseVault(text: string): EncryptionResult & {
  keyMetadata?: KeyDerivationOptions;
} {
  if (typeof text !== 'string') {
    throw new Error('Invalid vault format: vault must be a string');
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch (e) {
    throw new Error('Invalid vault format: vault is not valid JSON');
  }
  if (
    !isPlainObject(payload) ||
    typeof payload.data !== 'string' ||
    typeof payload.iv !== 'string' ||
    typeof payload.salt !== 'string'
  ) {
    throw new Error(
      'Invalid vault format: missing or invalid data, iv, or salt fields',
    );
  }
  return payload as EncryptionResult & {
    keyMetadata?: KeyDerivationOptions;
  };
}

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
  const vector = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const key = unwrapKey(encryptionKey);

  const buf = await globalThis.crypto.subtle.encrypt(
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
  const payload = parseVault(text);
  const { salt, keyMetadata } = payload;
  const cryptoKey = unwrapKey(
    encryptionKey ||
      (await keyFromPassword(
        password,
        salt,
        false,
        // A vault without keyMetadata is a legacy vault: use the legacy
        // derivation params explicitly so these vaults still unlock, while
        // the public `keyFromPassword` default stays at the modern params.
        keyMetadata ?? OLD_DERIVATION_PARAMS,
      )),
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
  const payload = parseVault(text);
  const { salt, keyMetadata } = payload;
  const key = await keyFromPassword(
    password,
    salt,
    true,
    // Legacy vaults carry no keyMetadata; derive with the legacy params so
    // the exported key actually unlocks the vault.
    keyMetadata ?? OLD_DERIVATION_PARAMS,
  );
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

  let decryptedData: Uint8Array;
  try {
    // Only the WebCrypto decryption failure (wrong key or tampered
    // ciphertext) is translated into a uniform "Incorrect password" error;
    // keeping this indistinguishable avoids a decryption oracle.
    const result = await crypto.subtle.decrypt(
      { name: DERIVED_KEY_FORMAT, iv: vector },
      key,
      encryptedData,
    );
    decryptedData = new Uint8Array(result);
  } catch (e) {
    throw new Error('Incorrect password');
  }

  // Decryption succeeded, so the password was correct; failures below mean
  // the plaintext itself is unusable and must surface as a distinct error
  // rather than masquerading as a wrong password.
  const decryptedStr = Buffer.from(decryptedData).toString(STRING_ENCODING);
  try {
    return JSON.parse(decryptedStr);
  } catch (e) {
    throw new Error('Corrupt vault: decrypted payload is not valid JSON');
  }
}

/**
 * Receives an exported CryptoKey string and creates a key.
 *
 * This function supports both JsonWebKey's and exported EncryptionKey's.
 * It will return a CryptoKey for the former, and an EncryptionKey for the latter.
 *
 * @param keyString - The key string to import.
 * @returns An EncryptionKey or a CryptoKey.
 */
export async function importKey(
  keyString: string,
): Promise<EncryptionKey | CryptoKey> {
  let exportedEncryptionKey: unknown;
  try {
    exportedEncryptionKey = JSON.parse(keyString);
  } catch (e) {
    throw new Error('Invalid key string: not valid JSON');
  }

  if (isExportedEncryptionKey(exportedEncryptionKey)) {
    return {
      key: await globalThis.crypto.subtle.importKey(
        EXPORT_FORMAT,
        exportedEncryptionKey.key,
        DERIVED_KEY_FORMAT,
        true,
        ['encrypt', 'decrypt'],
      ),
      derivationOptions: exportedEncryptionKey.derivationOptions,
    };
  }

  return await globalThis.crypto.subtle.importKey(
    EXPORT_FORMAT,
    exportedEncryptionKey,
    DERIVED_KEY_FORMAT,
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Exports a key string from a CryptoKey or from an
 * EncryptionKey instance.
 *
 * @param encryptionKey - The CryptoKey or EncryptionKey to export.
 * @returns A key string.
 */
export async function exportKey(
  encryptionKey: CryptoKey | EncryptionKey,
): Promise<string> {
  if (isEncryptionKey(encryptionKey)) {
    return JSON.stringify({
      key: await globalThis.crypto.subtle.exportKey(
        EXPORT_FORMAT,
        encryptionKey.key,
      ),
      derivationOptions: encryptionKey.derivationOptions,
    });
  }

  return JSON.stringify(
    await globalThis.crypto.subtle.exportKey(EXPORT_FORMAT, encryptionKey),
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
  opts: KeyDerivationOptions = DEFAULT_DERIVATION_PARAMS,
): Promise<CryptoKey | EncryptionKey> {
  // Legacy vaults (created before keyMetadata was recorded) are still
  // handled by passing OLD_DERIVATION_PARAMS explicitly from the decrypt
  // path; the public default is now the modern derivation params instead of
  // the weak 10,000-iteration legacy ones.
  validateKeyDerivationOptions(opts);

  const passBuffer = Buffer.from(password, STRING_ENCODING);
  const saltBuffer = Buffer.from(salt, 'base64');
  if (saltBuffer.byteLength < MIN_SALT_BYTE_LENGTH) {
    passBuffer.fill(0);
    throw new Error(
      `Invalid salt: must decode to at least ${MIN_SALT_BYTE_LENGTH} bytes`,
    );
  }

  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    passBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey'],
  );

  const derivedKey = await globalThis.crypto.subtle.deriveKey(
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

  // Scrub the password bytes: the imported CryptoKey is non-extractable and
  // lives inside WebCrypto, while this raw copy would otherwise linger in
  // the JS heap until garbage collection.
  passBuffer.fill(0);

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
  globalThis.crypto.getRandomValues(view);
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
 * Updates the provided vault, re-encrypting
 * data with a safer algorithm if one is available.
 *
 * If the provided vault is already using the latest available encryption method,
 * it is returned as is.
 *
 * @param vault - The vault to update.
 * @param password - The password to use for encryption.
 * @param targetDerivationParams - The options to use for key derivation.
 * @returns A promise resolving to the updated vault.
 */
export async function updateVault(
  vault: string,
  password: string,
  targetDerivationParams = DEFAULT_DERIVATION_PARAMS,
): Promise<string> {
  if (isVaultUpdated(vault, targetDerivationParams)) {
    return vault;
  }

  return encrypt(
    password,
    await decrypt(password, vault),
    undefined,
    undefined,
    targetDerivationParams,
  );
}

/**
 * Updates the provided vault and exported key, re-encrypting
 * data with a safer algorithm if one is available.
 *
 * If the provided vault is already using the latest available encryption method,
 * it is returned as is.
 *
 * @param encryptionResult - The encrypted data to update.
 * @param password - The password to use for encryption.
 * @param targetDerivationParams - The options to use for key derivation.
 * @returns A promise resolving to the updated encrypted data and exported key.
 */
export async function updateVaultWithDetail(
  encryptionResult: DetailedEncryptionResult,
  password: string,
  targetDerivationParams = DEFAULT_DERIVATION_PARAMS,
): Promise<DetailedEncryptionResult> {
  if (isVaultUpdated(encryptionResult.vault, targetDerivationParams)) {
    return encryptionResult;
  }

  return encryptWithDetail(
    password,
    await decrypt(password, encryptionResult.vault),
    undefined,
    targetDerivationParams,
  );
}

/**
 * Checks if the provided key is an `EncryptionKey`.
 *
 * @param encryptionKey - The object to check.
 * @returns Whether or not the key is an `EncryptionKey`.
 */
function isEncryptionKey(
  encryptionKey: unknown,
): encryptionKey is EncryptionKey {
  return (
    isPlainObject(encryptionKey) &&
    hasProperty(encryptionKey, 'key') &&
    hasProperty(encryptionKey, 'derivationOptions') &&
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
function isKeyDerivationOptions(
  derivationOptions: unknown,
): derivationOptions is KeyDerivationOptions {
  // Property presence alone is not enough: a crafted vault could carry
  // `"params": null`, which passes the property check and then crashes on
  // destructuring with a raw TypeError instead of the intended typed error.
  if (
    !isPlainObject(derivationOptions) ||
    !hasProperty(derivationOptions, 'algorithm') ||
    !hasProperty(derivationOptions, 'params') ||
    !isPlainObject(derivationOptions.params) ||
    !hasProperty(derivationOptions.params, 'iterations') ||
    typeof derivationOptions.params.iterations !== 'number'
  ) {
    return false;
  }
  return true;
}

/**
 * Checks if the provided key is an `ExportedEncryptionKey`.
 *
 * @param exportedKey - The object to check.
 * @returns Whether or not the object is an `ExportedEncryptionKey`.
 */
function isExportedEncryptionKey(
  exportedKey: unknown,
): exportedKey is ExportedEncryptionKey {
  return (
    isPlainObject(exportedKey) &&
    hasProperty(exportedKey, 'key') &&
    hasProperty(exportedKey, 'derivationOptions') &&
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
function unwrapKey(encryptionKey: EncryptionKey | CryptoKey): CryptoKey {
  return isEncryptionKey(encryptionKey) ? encryptionKey.key : encryptionKey;
}

/**
 * Checks if the provided vault is an updated encryption format.
 *
 * @param vault - The vault to check.
 * @param targetDerivationParams - The options to use for key derivation.
 * @returns Whether or not the vault is an updated encryption format.
 */
export function isVaultUpdated(
  vault: string,
  targetDerivationParams = DEFAULT_DERIVATION_PARAMS,
): boolean {
  let payload: unknown;
  try {
    payload = JSON.parse(vault);
  } catch (e) {
    // A non-JSON vault cannot be in the updated format.
    return false;
  }
  if (!isPlainObject(payload)) {
    return false;
  }
  const { keyMetadata } = payload;
  return (
    isKeyDerivationOptions(keyMetadata) &&
    keyMetadata.algorithm === targetDerivationParams.algorithm &&
    keyMetadata.params.iterations === targetDerivationParams.params.iterations
  );
}
