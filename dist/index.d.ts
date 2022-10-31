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
export declare function encrypt<R>(password: string, dataObj: R, key?: CryptoKey, salt?: string): Promise<string>;
/**
 * Encrypts a data object that can be any serializable value using
 * a provided password.
 *
 * @param {string} password - password to use for encryption
 * @param {R} dataObj - data to encrypt
 * @param {R} salt - salt used to encrypt
 * @returns {Promise<DetailedEncryptionResult>} object with vault and exportedKeyString
 */
export declare function encryptWithDetail<R>(password: string, dataObj: R, salt?: string): Promise<DetailedEncryptionResult>;
/**
 * Encrypts the provided serializable javascript object using the
 * provided CryptoKey and returns an object containing the cypher text and
 * the initialization vector used.
 * @param {CryptoKey} key - CryptoKey to encrypt with
 * @param {R} dataObj - Serializable javascript object to encrypt
 * @returns {EncryptionResult}
 */
export declare function encryptWithKey<R>(key: CryptoKey, dataObj: R): Promise<EncryptionResult>;
/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value
 * @param {string} password - password to decrypt with
 * @param {string} text - cypher text to decrypt
 * @param {CryptoKey} key - a key to use for decrypting
 * @returns {object}
 */
export declare function decrypt(password: string, text: string, key?: CryptoKey): Promise<unknown>;
/**
 * Given a password and a cypher text, decrypts the text and returns
 * the resulting value, keyString, and salt
 * @param {string} password - password to decrypt with
 * @param {string} text - cypher text to decrypt
 * @returns {object}
 */
export declare function decryptWithDetail(password: string, text: string): Promise<DetailedDecryptResult>;
/**
 * Given a CryptoKey and an EncryptionResult object containing the initialization
 * vector (iv) and data to decrypt, return the resulting decrypted value.
 * @param {CryptoKey} key - CryptoKey to decrypt with
 * @param {EncryptionResult} payload - payload returned from an encryption method
 */
export declare function decryptWithKey<R>(key: CryptoKey, payload: EncryptionResult): Promise<R>;
/**
 * Receives an exported CryptoKey string and creates a key
 * @param {string} keyString - keyString to import
 * @returns {CryptoKey}
 */
export declare function createKeyFromString(keyString: string): Promise<CryptoKey>;
/**
 * Receives an exported CryptoKey string, creates a key,
 * and decrypts cipher text with the reconstructed key
 * @param {CryptoKey} key - key to export
 * @returns {string}
 */
export declare function exportKey(key: CryptoKey): Promise<string>;
/**
 * Generate a CryptoKey from a password and random salt
 * @param {string} password - The password to use to generate key
 * @param {string} salt - The salt string to use in key derivation
 */
export declare function keyFromPassword(password: string, salt: string): Promise<CryptoKey>;
/**
 * Converts a hex string into a buffer.
 * @param {string} str - hex encoded string
 * @returns {Uint8Array}
 */
export declare function serializeBufferFromStorage(str: string): Uint8Array;
/**
 * Converts a buffer into a hex string ready for storage
 * @param {Uint8Array} buffer - Buffer to serialize
 * @returns {string} hex encoded string
 */
export declare function serializeBufferForStorage(buffer: Uint8Array): string;
/**
 * Generates a random string for use as a salt in CryptoKey generation
 * @param {number} byteCount - Number of bytes to generate
 * @returns {string} randomly generated string
 */
export declare function generateSalt(byteCount?: number): string;
export {};
