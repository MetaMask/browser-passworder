interface DetailedEncryptionResult {
    vault: string;
    exportedKeyString: string;
}
interface EncryptionResult {
    data: string;
    iv: string;
    salt?: string;
}
interface DetailedDecryptResult {
    exportedKeyString: string;
    vault: unknown;
    salt: string;
}
/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param {string} password - password to use for encryption
 * @param {R} dataObj - data to encrypt
 * @param {CryptoKey} key - a CryptoKey instance
 * @param {string} salt - salt used to encrypt
 * @returns {Promise<string>} cypher text
 */
declare function encrypt<R>(password: string, dataObj: R, key?: CryptoKey, salt?: string): Promise<string>;
/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param {string} password - password to use for encryption
 * @param {R} dataObj - data to encrypt
 * @returns {Promise<DetailedEncryptionResult>} object with vault and exportedKeyString
 */
declare function encryptWithDetail<R>(password: string, dataObj: R): Promise<DetailedEncryptionResult>;
/**
 * Encrypts the provided serializable javascript object using the
 * provided CryptoKey and returns an object containing the cypher text and
 * the initialization vector used.
 * @param {CryptoKey} key - CryptoKey to encrypt with
 * @param {R} dataObj - Serializable javascript object to encrypt
 * @returns {EncryptionResult}
 */
declare function encryptWithKey<R>(key: CryptoKey, dataObj: R): Promise<EncryptionResult>;
/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value
 * @param {string} password - password to decrypt with
 * @param {string} text - cypher text to decrypt
 * @param {CryptoKey} key - a key to use for decrypting
 * @returns {object}
 */
declare function decrypt(password: string, text: string, key?: CryptoKey): Promise<unknown>;
/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value, keyString, and salt
 * @param {string} password - password to decrypt with
 * @param {string} text - cypher text to decrypt
 * @returns {object}
 */
declare function decryptWithDetail(password: string, text: string): Promise<DetailedDecryptResult>;
/**
 * Receives an exported CryptoKey string and creates a key
 * @param {string} keyString - keyString to import
 * @returns {CryptoKey}
 */
declare function createKeyFromString(keyString: string): Promise<CryptoKey>;
/**
 * Given a CryptoKey and an EncryptionResult object containing the initialization
 * vector (iv) and data to decrypt, return the resulting decrypted value.
 * @param {CryptoKey} key - CryptoKey to decrypt with
 * @param {EncryptionResult} payload - payload returned from an encryption method
 */
declare function decryptWithKey<R>(key: CryptoKey, payload: EncryptionResult): Promise<R>;
/**
 * Generate a CryptoKey from a password and random salt
 * @param {string} password - The password to use to generate key
 * @param {string} salt - The salt string to use in key derivation
 */
declare function keyFromPassword(password: string, salt: string): Promise<CryptoKey>;
/**
 * Converts a hex string into a buffer.
 * @param {string} str - hex encoded string
 * @returns {Uint8Array}
 */
declare function serializeBufferFromStorage(str: string): Uint8Array;
/**
 * Converts a buffer into a hex string ready for storage
 * @param {Uint8Array} buffer - Buffer to serialize
 * @returns {string} hex encoded string
 */
declare function serializeBufferForStorage(buffer: Uint8Array): string;
/**
 * Generates a random string for use as a salt in CryptoKey generation
 * @param {number} byteCount - Number of bytes to generate
 * @returns {string} randomly generated string
 */
declare function generateSalt(byteCount?: number): string;
declare const _default: {
    encrypt: typeof encrypt;
    decrypt: typeof decrypt;
    keyFromPassword: typeof keyFromPassword;
    encryptWithKey: typeof encryptWithKey;
    decryptWithKey: typeof decryptWithKey;
    encryptWithDetail: typeof encryptWithDetail;
    decryptWithDetail: typeof decryptWithDetail;
    createKeyFromString: typeof createKeyFromString;
    serializeBufferForStorage: typeof serializeBufferForStorage;
    serializeBufferFromStorage: typeof serializeBufferFromStorage;
    generateSalt: typeof generateSalt;
};
export = _default;
