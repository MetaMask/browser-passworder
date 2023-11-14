import path from 'path';
import { test, expect } from '@playwright/test';

import * as Encryptor from '../src';

declare global {
  // Lint rule ignored to allow for declaration merging
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface Window {
    encryptor: typeof Encryptor;
  }
}

const testPagePath = path.resolve(__dirname, 'index.html');

const OLD_SAMPLE_EXPORTED_KEY =
  '{"alg":"A256GCM","ext":true,"k":"leW0IR00ACQp3SoWuITXQComCte7lwKLR9ztPlGkFeM","key_ops":["encrypt","decrypt"],"kty":"oct"}';
const SAMPLE_EXPORTED_KEY =
  '{"key":{"alg":"A256GCM","ext":true,"k":"leW0IR00ACQp3SoWuITXQComCte7lwKLR9ztPlGkFeM","key_ops":["encrypt","decrypt"],"kty":"oct"},"derivationOptions":{"algorithm":"PBKDF2","params":{"iterations":10000}}}';

test.beforeEach(async ({ page }) => {
  await page.goto(`file://${testPagePath}`);
});

test('encryptor:serializeBufferForStorage', async ({ page }) => {
  const output = await page.evaluate(() => {
    const buffer = new Uint8Array(2);
    buffer[0] = 16;
    buffer[1] = 1;
    return window.encryptor.serializeBufferForStorage(buffer);
  });

  const expected = '0x1001';
  expect(output).toBe(expected);
});

test('encryptor:serializeBufferFromStorage', async ({ page }) => {
  const output = await page.evaluate(() =>
    window.encryptor.serializeBufferFromStorage('0x1001'),
  );

  expect(output[0]).toBe(16);
  expect(output[1]).toBe(1);
});

test('encryptor:generateSalt generates 32 byte Base64-encoded string by default', async ({
  page,
}) => {
  const salt = await page.evaluate(() => window.encryptor.generateSalt());

  expect(salt.length).toBe(44);
  const decodedSalt = await page.evaluate((args) => atob(args.salt), { salt });
  expect(decodedSalt.length).toBe(32);
});

test('encryptor:generateSalt generates 32 byte Base64-encoded string', async ({
  page,
}) => {
  const salt = await page.evaluate(() => window.encryptor.generateSalt(32));

  expect(salt.length).toBe(44);
  const decodedSalt = await page.evaluate((args) => atob(args.salt), { salt });
  expect(decodedSalt.length).toBe(32);
});

test('encryptor:generateSalt generates 16 byte Base64-encoded string', async ({
  page,
}) => {
  const salt = await page.evaluate(() => window.encryptor.generateSalt(16));

  expect(salt.length).toBe(24);
  const decodedSalt = await page.evaluate((args) => atob(args.salt), { salt });
  expect(decodedSalt.length).toBe(16);
});

test('encryptor:generateSalt generates 64 byte Base64-encoded string', async ({
  page,
}) => {
  const salt = await page.evaluate(() => window.encryptor.generateSalt(64));

  expect(salt.length).toBe(88);
  const decodedSalt = await page.evaluate((args) => atob(args.salt), { salt });
  expect(decodedSalt.length).toBe(64);
});

test('encryptor:encrypt & decrypt', async ({ page }) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  const encryptedString = await page.evaluate(
    async (args) => await window.encryptor.encrypt(args.password, args.data),
    { data, password },
  );
  expect(typeof encryptedString).toBe('string');

  const decryptedObj = await page.evaluate(
    async (args) =>
      await window.encryptor.decrypt(args.password, args.encryptedString),
    { encryptedString, password },
  );
  expect(decryptedObj).toStrictEqual(data);
});

test('encryptor:encryptWithDetail returns vault', async ({ page }) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  const encryptedDetail = await page.evaluate(
    async (args) =>
      await window.encryptor.encryptWithDetail(args.password, args.data),
    { data, password },
  );
  expect(typeof encryptedDetail.vault).toBe('string');
  expect(typeof encryptedDetail.exportedKeyString).toBe('string');
});

test('encryptor:encrypt & decrypt with wrong password', async ({ page }) => {
  const password = 'a sample passw0rd';
  const wrongPassword = 'a wrong password';
  const data = { foo: 'data to encrypt' };

  const encryptedString = await page.evaluate(
    async (args) => await window.encryptor.encrypt(args.password, args.data),
    { data, password },
  );

  await expect(
    page.evaluate(
      async (args) =>
        await window.encryptor.decrypt(
          args.wrongPassword,
          args.encryptedString,
        ),
      { encryptedString, wrongPassword },
    ),
  ).rejects.toThrow('Incorrect password');
});

/**
 * This is the encrypted object `{ foo: 'data to encrypt' }`, which was
 * encrypted using v2.0.3 of this library with the password
 * `a sample passw0rd` and 10000 iterations. This should be left unmodified,
 * as it's used to test that decrypting older encrypted data continues to work.
 */
const oldSampleEncryptedData: Encryptor.EncryptionResult = {
  data: 'bfCvija6QfwqARmHsKT7ZR0GHi8yjz7iVEZodRVx3xI2yzFHwq7+B/U=',
  iv: 'N9s46G5sp37A7wtf3vo/LA==',
  salt: '+uzzUKmbAdwkjw8rILhJvZE9dOfz2ecF5Gtf7yNkyyE=',
};

/**
 * This is the encrypted object `{ foo: 'data to encrypt' }`, which was
 * encrypted using v5.0.0 of this library with the password
 * `a sample passw0rd` and 900.000 iterations. This should be left unmodified,
 * as it's used to test that decrypting older encrypted data continues to work.
 */
const sampleEncryptedData: Encryptor.EncryptionResult = {
  data: 'WQbagUPb+XLvSR+U7sV9jzyS+5UZfVjBiWpmJjPOlJT93dJo9kltpls=',
  iv: '7NsJ8mmL1DgC5LlsIyaIXA==',
  salt: 'sysHvNRoWykN/JVUSpBwXhmp0llTMQabfY7zucEfAJg=',
  keyMetadata: {
    algorithm: 'PBKDF2',
    params: {
      iterations: 900000,
    },
  },
};

[sampleEncryptedData, oldSampleEncryptedData].forEach((testEncryptedData) => {
  test.describe(`${
    testEncryptedData === oldSampleEncryptedData ? 'without' : 'with'
  } key derivation function metadata`, () => {
    test('encryptor:decrypt encrypted data', async ({ page }) => {
      const password = 'a sample passw0rd';
      const expectedData = { foo: 'data to encrypt' };

      const decryptedData = await page.evaluate(
        async (args) =>
          await window.encryptor.decrypt(
            args.password,
            JSON.stringify(args.testEncryptedData),
          ),
        { testEncryptedData, password },
      );

      expect(decryptedData).toStrictEqual(expectedData);
    });

    test('encryptor:decrypt encrypted data using wrong password', async ({
      page,
    }) => {
      const wrongPassword = 'a wrong password';

      await expect(
        page.evaluate(
          async (args) =>
            await window.encryptor.decrypt(
              args.wrongPassword,
              JSON.stringify(args.testEncryptedData),
            ),
          { testEncryptedData, wrongPassword },
        ),
      ).rejects.toThrow('Incorrect password');
    });

    test('encryptor:decryptWithDetail returns same vault as decrypt', async ({
      page,
    }) => {
      const password = 'a sample passw0rd';

      const decryptResult = await page.evaluate(
        async (args) => {
          return await window.encryptor.decrypt(
            args.password,
            JSON.stringify(args.testEncryptedData),
          );
        },
        { password, testEncryptedData },
      );

      const decryptWithDetailResult = await page.evaluate(
        async (args) => {
          return await window.encryptor.decryptWithDetail(
            args.password,
            JSON.stringify(args.testEncryptedData),
          );
        },
        { password, testEncryptedData },
      );

      expect(JSON.stringify(decryptResult)).toStrictEqual(
        JSON.stringify(decryptWithDetailResult.vault),
      );
      expect(Object.keys(decryptWithDetailResult).length).toBe(3);
      expect(typeof decryptWithDetailResult.exportedKeyString).toStrictEqual(
        'string',
      );
    });

    test('encryptor:decrypt encrypted data using key', async ({ page }) => {
      const password = 'a sample passw0rd';
      const expectedData = { foo: 'data to encrypt' };
      const { salt } = testEncryptedData;

      const decryptedData = await page.evaluate(
        async (args) => {
          const key = await window.encryptor.keyFromPassword(
            args.password,
            args.salt as string,
            false,
            args.testEncryptedData.keyMetadata,
          );
          return await window.encryptor.decryptWithKey(
            key,
            args.testEncryptedData,
          );
        },
        { testEncryptedData, password, salt },
      );

      expect(decryptedData).toStrictEqual(expectedData);
    });

    test('encryptor:decrypt encrypted data using key derived from wrong password', async ({
      page,
    }) => {
      const wrongPassword = 'a wrong password';

      await expect(
        page.evaluate(
          async (args) => {
            const key = await window.encryptor.keyFromPassword(
              args.wrongPassword,
              args.salt as string,
              false,
              args.encryptedPayload.keyMetadata,
            );
            return await window.encryptor.decryptWithKey(
              key,
              args.encryptedPayload,
            );
          },
          {
            encryptedPayload: testEncryptedData,
            salt: testEncryptedData.salt,
            wrongPassword,
          },
        ),
      ).rejects.toThrow('Incorrect password');
    });
  });
});

test('encryptor:encrypt using key then decrypt', async ({ page }) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };
  const salt = await page.evaluate(() => window.encryptor.generateSalt());

  const encryptedData = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.keyFromPassword(
        args.password,
        args.salt,
      );
      return await window.encryptor.encryptWithKey(key, args.data);
    },
    { data, password, salt },
  );
  expect(Object.keys(encryptedData).sort()).toStrictEqual([
    'data',
    'iv',
    'keyMetadata',
  ]);

  const encryptedString = JSON.stringify(
    Object.assign({}, encryptedData, { salt }),
  );
  const decryptedData = await page.evaluate(
    async (args) =>
      await window.encryptor.decrypt(args.password, args.encryptedString),
    { encryptedString, password },
  );

  expect(decryptedData).toStrictEqual(data);
});

test('encryptor:encrypt using key then decrypt using wrong password', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const wrongPassword = 'a wrong password';
  const data = { foo: 'data to encrypt' };
  const salt = await page.evaluate(() => window.encryptor.generateSalt());

  const encryptedData = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.keyFromPassword(
        args.password,
        args.salt,
      );
      return await window.encryptor.encryptWithKey(key, args.data);
    },
    { data, password, salt },
  );
  expect(Object.keys(encryptedData).sort()).toStrictEqual([
    'data',
    'iv',
    'keyMetadata',
  ]);

  const encryptedString = JSON.stringify(
    Object.assign({}, encryptedData, { salt }),
  );
  await expect(
    page.evaluate(
      async (args) =>
        await window.encryptor.decrypt(
          args.wrongPassword,
          args.encryptedString,
        ),
      { encryptedString, wrongPassword },
    ),
  ).rejects.toThrow('Incorrect password');
});

test('encryptor:encrypt then decrypt using key', async ({ page }) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  const encryptedString = await page.evaluate(
    async (args) => await window.encryptor.encrypt(args.password, args.data),
    { data, password },
  );
  expect(typeof encryptedString).toBe('string');
  const encryptedData = JSON.parse(encryptedString);
  const { salt } = encryptedData;
  const encryptedPayload = {
    data: encryptedData.data,
    iv: encryptedData.iv,
    keyMetadata: encryptedData.keyMetadata,
  };

  const decryptedData = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.keyFromPassword(
        args.password,
        args.salt,
        false,
        args.encryptedPayload.keyMetadata,
      );
      return await window.encryptor.decryptWithKey(key, args.encryptedPayload);
    },
    { encryptedPayload, password, salt },
  );

  expect(decryptedData).toStrictEqual(data);
});

test('encryptor:encrypt then decrypt using key derived from wrong password', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const wrongPassword = 'a wrong password';
  const data = { foo: 'data to encrypt' };

  const encryptedString = await page.evaluate(
    async (args) => await window.encryptor.encrypt(args.password, args.data),
    { data, password },
  );
  expect(typeof encryptedString).toBe('string');
  const encryptedData = JSON.parse(encryptedString);
  const { salt } = encryptedData;
  const encryptedPayload = {
    data: encryptedData.data,
    iv: encryptedData.iv,
  };

  await expect(
    page.evaluate(
      async (args) => {
        const key = await window.encryptor.keyFromPassword(
          args.wrongPassword,
          args.salt,
        );
        return await window.encryptor.decryptWithKey(
          key,
          args.encryptedPayload,
        );
      },
      { encryptedPayload, salt, wrongPassword },
    ),
  ).rejects.toThrow('Incorrect password');
});

test('encryptor:importKey generates valid CryptoKey using old key export format', async ({
  page,
}) => {
  const isKey = await page.evaluate(
    async (args) => {
      const encryptionKey = await window.encryptor.importKey(
        args.OLD_SAMPLE_EXPORTED_KEY,
      );
      return encryptionKey instanceof CryptoKey;
    },
    { OLD_SAMPLE_EXPORTED_KEY },
  );
  expect(isKey).toBe(true);
});

test('encryptor:importKey generates valid EncryptionKey using new key export format', async ({
  page,
}) => {
  const isKey = await page.evaluate(
    async (args) => {
      const encryptionKey = await window.encryptor.importKey(
        args.SAMPLE_EXPORTED_KEY,
      );
      return (
        !(encryptionKey instanceof CryptoKey) &&
        encryptionKey.key instanceof CryptoKey &&
        encryptionKey.derivationOptions.algorithm === 'PBKDF2' &&
        encryptionKey.derivationOptions.params.iterations === 10000
      );
    },
    { SAMPLE_EXPORTED_KEY },
  );
  expect(isKey).toBe(true);
});

[OLD_SAMPLE_EXPORTED_KEY, SAMPLE_EXPORTED_KEY].forEach((testKey) => {
  test.describe(`with the ${
    testKey === OLD_SAMPLE_EXPORTED_KEY ? 'old' : 'new'
  } exported key format`, () => {
    test('encryptor:exportKey generates valid CryptoKey string', async ({
      page,
    }) => {
      const keyString = await page.evaluate(
        async (args) => {
          const key = await window.encryptor.importKey(args.testKey);
          return await window.encryptor.exportKey(key);
        },
        { testKey },
      );
      expect(keyString).toStrictEqual(testKey);
    });
  });
});

test('encryptor:encryptWithDetail and decryptWithDetail provide same data', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  const { vault } = await page.evaluate(
    async (args) =>
      await window.encryptor.encryptWithDetail(args.password, args.data),
    { data, password },
  );

  const decryptedDetail = await page.evaluate(
    async (args) =>
      await window.encryptor.decryptWithDetail(args.password, args.data),
    { data: vault, password },
  );

  expect(JSON.stringify(decryptedDetail.vault)).toStrictEqual(
    JSON.stringify(data),
  );
});

test('encryptor:decryptWithKey provide same data when using exported key from encryptWithDetail', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  const { vault, exportedKeyString } = await page.evaluate(
    async (args) =>
      await window.encryptor.encryptWithDetail(args.password, args.data),
    { data, password },
  );

  // Use the exported key and vault to properly decrypt the data
  const decryptWithKeyResult = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.importKey(args.keyString);
      return await window.encryptor.decryptWithKey(key, JSON.parse(args.data));
    },
    { data: vault, keyString: exportedKeyString },
  );

  expect(JSON.stringify(decryptWithKeyResult)).toStrictEqual(
    JSON.stringify(data),
  );
});

test('encryptor:decryptWithDetail works with password after encryption with key', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const startingData = { foo: 'data to encrypt' };

  // Get an exported key to use
  const { salt, exportedKeyString } = await page.evaluate(
    async (args) => {
      const usedSalt = window.encryptor.generateSalt();
      const { exportedKeyString: newKeyString } =
        await window.encryptor.encryptWithDetail(
          args.password,
          args.data,
          usedSalt,
        );

      return {
        salt: usedSalt,
        exportedKeyString: newKeyString,
      };
    },
    { data: startingData, password },
  );

  // Update the data, encrypt using key
  const newData = { ...startingData, bar: 'more data' };
  const encryptWithKeyResult = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.importKey(args.keyString);
      return await window.encryptor.encryptWithKey(key, args.data);
    },
    { data: newData, keyString: exportedKeyString },
  );

  // Mock the encrypted object
  const decryptable = {
    ...encryptWithKeyResult,
    salt,
  };

  // Prove that a vault created with key can be decrypted with password
  const decryptedResult = await page.evaluate(
    async (args) =>
      await window.encryptor.decryptWithDetail(args.password, args.data),
    { password, data: JSON.stringify(decryptable) },
  );

  expect(JSON.stringify(decryptedResult.vault)).toStrictEqual(
    JSON.stringify(newData),
  );
});

test('encryptor:encryptWithKey works with decryptWithKey', async ({ page }) => {
  const password = 'a sample passw0rd';
  const startingData = { foo: 'data to encrypt' };

  // Get an exported key to use
  const exportedKeyString = await page.evaluate(
    async (args) => {
      const { exportedKeyString: newKeyString } =
        await window.encryptor.encryptWithDetail(args.password, args.data);

      return newKeyString;
    },
    { data: startingData, password },
  );

  // Update the data, encrypt using key
  const newData = { ...startingData, bar: 'more data' };
  const encryptWithKeyResult = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.importKey(args.keyString);
      const result = await window.encryptor.encryptWithKey(key, args.data);

      return {
        encryptWithKeyResult: result,
        exportedKeyString: await window.encryptor.exportKey(key),
      };
    },
    { data: newData, keyString: exportedKeyString },
  );

  // Prove that a vault created with key can be decrypted with password
  const decryptedResult = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.importKey(args.exportedKeyString);
      return await window.encryptor.decryptWithKey(key, args.data);
    },
    {
      exportedKeyString: encryptWithKeyResult.exportedKeyString,
      data: encryptWithKeyResult.encryptWithKeyResult,
    },
  );

  expect(JSON.stringify(decryptedResult)).toStrictEqual(
    JSON.stringify(newData),
  );
});

test('encryptor:keyFromPassword cannot be exported by default', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };
  const salt = await page.evaluate(() => window.encryptor.generateSalt());

  const exportResult = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.keyFromPassword(
        args.password,
        args.salt,
      );

      try {
        const result = await window.encryptor.exportKey(key);
        return result;
      } catch (e) {
        return 'error';
      }
    },
    { data, password, salt },
  );

  expect(exportResult).toStrictEqual('error');
});

test('encryptor:decrypt old encrypted data and re-encrypt with password', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const expectedData = { foo: 'data to encrypt' };

  const decryptedData = await page.evaluate(
    async (args) =>
      await window.encryptor.decrypt(
        args.password,
        JSON.stringify(args.encryptedData),
      ),
    { encryptedData: oldSampleEncryptedData, password },
  );
  const encryptedData: Encryptor.EncryptionResult = JSON.parse(
    await page.evaluate(
      async (args) => await window.encryptor.encrypt(args.password, args.data),
      { data: decryptedData, password },
    ),
  );

  expect(decryptedData).toStrictEqual(expectedData);
  expect(encryptedData).toHaveProperty('keyMetadata');
  expect(encryptedData.keyMetadata).toStrictEqual({
    algorithm: 'PBKDF2',
    params: {
      iterations: 900000,
    },
  });
});

test('encryptor:encrypt with arbitrary key derivation options then decrypt', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };
  const salt = await page.evaluate(() => window.encryptor.generateSalt());

  const encryptedString = await page.evaluate(
    async (args) =>
      await window.encryptor.encrypt(
        args.password,
        args.data,
        undefined,
        args.salt,
        {
          algorithm: 'PBKDF2',
          params: {
            iterations: 100_000,
          },
        },
      ),
    { data, password, salt },
  );

  const decryptedObj = await page.evaluate(
    async (args) =>
      await window.encryptor.decrypt(args.password, args.encryptedString),
    { encryptedString, password },
  );

  expect(decryptedObj).toStrictEqual(data);
});

test('encryptor:encryptWithDetail with arbitrary key derivation options then decrypt', async ({
  page,
}) => {
  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };
  const salt = await page.evaluate(() => window.encryptor.generateSalt());

  const { vault: encryptedString } = await page.evaluate(
    async (args) =>
      await window.encryptor.encryptWithDetail(
        args.password,
        args.data,
        args.salt,
        {
          algorithm: 'PBKDF2',
          params: {
            iterations: 100_000,
          },
        },
      ),
    { data, password, salt },
  );

  const { vault: decryptedObj } = await page.evaluate(
    async (args) =>
      await window.encryptor.decryptWithDetail(
        args.password,
        args.encryptedString,
      ),
    { encryptedString, password },
  );

  expect(decryptedObj).toStrictEqual(data);
});

test.describe('encryptor:updateVault', async () => {
  test.describe('with old vault format', async () => {
    test('should return a vault encrypted with a key derived with new key derivation options', async ({
      page,
    }) => {
      const updatedVault = await page.evaluate(
        async (args) => {
          const vault = await window.encryptor.updateVault(
            args.vault,
            args.password,
          );
          return JSON.parse(vault);
        },
        {
          vault: JSON.stringify(oldSampleEncryptedData),
          password: 'a sample passw0rd',
        },
      );

      expect(updatedVault).toHaveProperty('keyMetadata');
      expect(updatedVault.keyMetadata).toStrictEqual(
        sampleEncryptedData.keyMetadata,
      );
    });

    test('should return a vault that can be decrypted with the same password', async ({
      page,
    }) => {
      const password = 'a sample passw0rd';
      const updatedVault = await page.evaluate(
        async (args) => window.encryptor.updateVault(args.vault, args.password),
        {
          vault: JSON.stringify(oldSampleEncryptedData),
          password,
        },
      );

      const decryptedObj = await page.evaluate(
        async (args) =>
          await window.encryptor.decrypt(args.password, args.encryptedString),
        {
          encryptedString: updatedVault,
          password,
        },
      );

      expect(decryptedObj).toStrictEqual({ foo: 'data to encrypt' });
    });
  });

  test.describe('with new vault format', async () => {
    test('should return the same vault', async ({ page }) => {
      const updatedVault = await page.evaluate(
        async (args) => {
          const vault = await window.encryptor.updateVault(
            args.vault,
            args.password,
          );
          return JSON.parse(vault);
        },
        {
          vault: JSON.stringify(sampleEncryptedData),
          password: 'a sample passw0rd',
        },
      );

      expect(updatedVault).toStrictEqual(sampleEncryptedData);
    });
  });
});

test.describe('encryptor:updateVaultWithDetail', async () => {
  test.describe('with old vault format', async () => {
    test('should return a vault encrypted with a key derived with new key derivation options', async ({
      page,
    }) => {
      const detailedVault: Encryptor.DetailedEncryptionResult = {
        vault: JSON.stringify(oldSampleEncryptedData),
        exportedKeyString: OLD_SAMPLE_EXPORTED_KEY,
      };

      const updatedVault = await page.evaluate(
        async (args) =>
          window.encryptor.updateVaultWithDetail(
            args.detailedVault,
            args.password,
          ),
        {
          detailedVault,
          password: 'a sample passw0rd',
        },
      );
      const vault = JSON.parse(updatedVault.vault);

      expect(vault).toHaveProperty('keyMetadata');
      expect(vault.keyMetadata).toStrictEqual(sampleEncryptedData.keyMetadata);
    });

    test('should return a vault that can be decrypted with the same password', async ({
      page,
    }) => {
      const password = 'a sample passw0rd';
      const detailedVault: Encryptor.DetailedEncryptionResult = {
        vault: JSON.stringify(oldSampleEncryptedData),
        exportedKeyString: OLD_SAMPLE_EXPORTED_KEY,
      };
      const updatedVault = await page.evaluate(
        async (args) =>
          window.encryptor.updateVaultWithDetail(
            args.detailedVault,
            args.password,
          ),
        {
          detailedVault,
          password,
        },
      );

      const decryptedObj = await page.evaluate(
        async (args) =>
          await window.encryptor.decrypt(args.password, args.encryptedString),
        {
          encryptedString: updatedVault.vault,
          password,
        },
      );

      expect(decryptedObj).toStrictEqual({ foo: 'data to encrypt' });
    });
  });

  test.describe('with new vault format', async () => {
    test('should return the same vault', async ({ page }) => {
      const detailedVault: Encryptor.DetailedEncryptionResult = {
        vault: JSON.stringify(sampleEncryptedData),
        exportedKeyString: SAMPLE_EXPORTED_KEY,
      };

      const updatedVault = await page.evaluate(
        async (args) =>
          window.encryptor.updateVaultWithDetail(
            args.detailedVault,
            args.password,
          ),
        {
          detailedVault,
          password: 'a sample passw0rd',
        },
      );

      expect(JSON.parse(updatedVault.vault)).toStrictEqual(sampleEncryptedData);
    });
  });
});

test.describe('encryptor:isVaultUpdated', async () => {
  test('should return true with new vault format', async ({ page }) => {
    const isVaultUpdated = await page.evaluate(
      async (args) => window.encryptor.isVaultUpdated(args.vault),
      { vault: JSON.stringify(sampleEncryptedData) },
    );

    expect(isVaultUpdated).toBe(true);
  });

  test('should return false with old vault format', async ({ page }) => {
    const isVaultUpdated = await page.evaluate(
      async (args) => window.encryptor.isVaultUpdated(args.vault),
      { vault: JSON.stringify(oldSampleEncryptedData) },
    );

    expect(isVaultUpdated).toBe(false);
  });
});
