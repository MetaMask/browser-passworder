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

const SAMPLE_EXPORTED_KEY =
  '{"alg":"A256GCM","ext":true,"k":"leW0IR00ACQp3SoWuITXQComCte7lwKLR9ztPlGkFeM","key_ops":["encrypt","decrypt"],"kty":"oct"}';

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
 * `a sample passw0rd`. This should be left unmodified, as it's used to test
 * that decrypting older encrypted data continues to work.
 */
const sampleEncryptedDataV1 = {
  data: 'bfCvija6QfwqARmHsKT7ZR0GHi8yjz7iVEZodRVx3xI2yzFHwq7+B/U=',
  iv: 'N9s46G5sp37A7wtf3vo/LA==',
  salt: '+uzzUKmbAdwkjw8rILhJvZE9dOfz2ecF5Gtf7yNkyyE=',
};

const sampleEncryptedDataV2 = {
  version: '2.0',
  data: '/7Pqz+WFluKFlmPhG3fKEHalzZqEvwvtFZibXVK3133fhtp72MJnEmY=',
  iv: '3DkwjtOhrfjmmhueQL/hOA==',
  salt: '0u9YlQFIaC8l8nUnq+K0M8/cMy4xKYEeHE6XCSGuTtQ=',
};

test.describe('with version 1.0', () => {
  test('encryptor:decrypt encrypted data', async ({ page }) => {
    const password = 'a sample passw0rd';
    const expectedData = { foo: 'data to encrypt' };

    const decryptedData = await page.evaluate(
      async (args) =>
        await window.encryptor.decrypt(
          args.password,
          JSON.stringify(args.sampleEncryptedDataV1),
        ),
      { sampleEncryptedDataV1, password },
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
            JSON.stringify(args.sampleEncryptedDataV1),
          ),
        { sampleEncryptedDataV1, wrongPassword },
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
          JSON.stringify(args.sampleEncryptedDataV1),
        );
      },
      { password, sampleEncryptedDataV1 },
    );

    const decryptWithDetailResult = await page.evaluate(
      async (args) => {
        return await window.encryptor.decryptWithDetail(
          args.password,
          JSON.stringify(args.sampleEncryptedDataV1),
        );
      },
      { password, sampleEncryptedDataV1 },
    );

    expect(JSON.stringify(decryptResult)).toStrictEqual(
      JSON.stringify(decryptWithDetailResult.vault),
    );
    expect(Object.keys(decryptWithDetailResult).length).toBe(3);
    expect(typeof decryptWithDetailResult.exportedKeyString).toStrictEqual(
      'string',
    );
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
      'version',
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
      'version',
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
      version: encryptedData.version,
    };

    const decryptedData = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.keyFromPassword(
          args.password,
          args.salt,
        );
        return await window.encryptor.decryptWithKey(
          key,
          args.encryptedPayload,
        );
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
      version: encryptedData.version,
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

  test('encryptor:decrypt encrypted data using key', async ({ page }) => {
    const password = 'a sample passw0rd';
    const expectedData = { foo: 'data to encrypt' };
    const encryptedPayload = {
      data: sampleEncryptedDataV1.data,
      iv: sampleEncryptedDataV1.iv,
    };
    const { salt } = sampleEncryptedDataV1;

    const decryptedData = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.keyFromPassword(
          args.password,
          args.salt,
          10000,
        );
        return await window.encryptor.decryptWithKey(
          key,
          args.encryptedPayload,
        );
      },
      { encryptedPayload, password, salt },
    );

    expect(decryptedData).toStrictEqual(expectedData);
  });

  test('encryptor:decrypt encrypted data using key derived from wrong password', async ({
    page,
  }) => {
    const wrongPassword = 'a wrong password';
    const encryptedPayload = {
      data: sampleEncryptedDataV1.data,
      iv: sampleEncryptedDataV1.iv,
    };
    const { salt } = sampleEncryptedDataV1;

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

  test('encryptor:importKey generates valid CryptoKey', async ({ page }) => {
    const isKey = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.importKey(args.SAMPLE_EXPORTED_KEY);
        return key instanceof CryptoKey;
      },
      { SAMPLE_EXPORTED_KEY },
    );
    expect(isKey).toBe(true);
  });

  test('encryptor:exportKey generates valid CryptoKey string', async ({
    page,
  }) => {
    const keyString = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.importKey(args.SAMPLE_EXPORTED_KEY);
        return await window.encryptor.exportKey(key);
      },
      { SAMPLE_EXPORTED_KEY },
    );
    expect(keyString).toStrictEqual(SAMPLE_EXPORTED_KEY);
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
        return await window.encryptor.decryptWithKey(
          key,
          JSON.parse(args.data),
        );
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

  test('encryptor:encryptWithKey works with decryptWithKey', async ({
    page,
  }) => {
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
});

test.describe('with version 2.0', () => {
  test('encryptor:decrypt encrypted data', async ({ page }) => {
    const password = 'a sample passw0rd';
    const expectedData = { foo: 'data to encrypt' };

    const decryptedData = await page.evaluate(
      async (args) =>
        await window.encryptor.decrypt(
          args.password,
          JSON.stringify(args.sampleEncryptedDataV2),
        ),
      { sampleEncryptedDataV2, password },
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
            JSON.stringify(args.sampleEncryptedDataV2),
          ),
        { sampleEncryptedDataV2, wrongPassword },
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
          JSON.stringify(args.sampleEncryptedDataV2),
        );
      },
      { password, sampleEncryptedDataV2 },
    );

    const decryptWithDetailResult = await page.evaluate(
      async (args) => {
        return await window.encryptor.decryptWithDetail(
          args.password,
          JSON.stringify(args.sampleEncryptedDataV2),
        );
      },
      { password, sampleEncryptedDataV2 },
    );

    expect(JSON.stringify(decryptResult)).toStrictEqual(
      JSON.stringify(decryptWithDetailResult.vault),
    );
    expect(Object.keys(decryptWithDetailResult).length).toBe(3);
    expect(typeof decryptWithDetailResult.exportedKeyString).toStrictEqual(
      'string',
    );
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
      'version',
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
      'version',
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
      version: encryptedData.version,
    };

    const decryptedData = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.keyFromPassword(
          args.password,
          args.salt,
        );
        return await window.encryptor.decryptWithKey(
          key,
          args.encryptedPayload,
        );
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
      version: encryptedData.version,
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

  test('encryptor:decrypt encrypted data using key', async ({ page }) => {
    const password = 'a sample passw0rd';
    const expectedData = { foo: 'data to encrypt' };
    const encryptedPayload = {
      data: sampleEncryptedDataV2.data,
      iv: sampleEncryptedDataV2.iv,
    };
    const { salt } = sampleEncryptedDataV2;

    const decryptedData = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.keyFromPassword(
          args.password,
          args.salt,
        );
        return await window.encryptor.decryptWithKey(
          key,
          args.encryptedPayload,
        );
      },
      { encryptedPayload, password, salt },
    );

    expect(decryptedData).toStrictEqual(expectedData);
  });

  test('encryptor:decrypt encrypted data using key derived from wrong password', async ({
    page,
  }) => {
    const wrongPassword = 'a wrong password';
    const encryptedPayload = {
      data: sampleEncryptedDataV2.data,
      iv: sampleEncryptedDataV2.iv,
    };
    const { salt } = sampleEncryptedDataV2;

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

  test('encryptor:importKey generates valid CryptoKey', async ({ page }) => {
    const isKey = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.importKey(args.SAMPLE_EXPORTED_KEY);
        return key instanceof CryptoKey;
      },
      { SAMPLE_EXPORTED_KEY },
    );
    expect(isKey).toBe(true);
  });

  test('encryptor:exportKey generates valid CryptoKey string', async ({
    page,
  }) => {
    const keyString = await page.evaluate(
      async (args) => {
        const key = await window.encryptor.importKey(args.SAMPLE_EXPORTED_KEY);
        return await window.encryptor.exportKey(key);
      },
      { SAMPLE_EXPORTED_KEY },
    );
    expect(keyString).toStrictEqual(SAMPLE_EXPORTED_KEY);
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
        return await window.encryptor.decryptWithKey(
          key,
          JSON.parse(args.data),
        );
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

  test('encryptor:encryptWithKey works with decryptWithKey', async ({
    page,
  }) => {
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
});
