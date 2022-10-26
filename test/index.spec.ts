import path from 'path';
import { test, expect } from '@playwright/test';

import * as Encryptor from '../src';

declare global {
  interface Window {
    encryptor: typeof Encryptor;
  }
}

const testPagePath = path.resolve(__dirname, 'index.html');

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
const sampleEncryptedData = {
  data: 'bfCvija6QfwqARmHsKT7ZR0GHi8yjz7iVEZodRVx3xI2yzFHwq7+B/U=',
  iv: 'N9s46G5sp37A7wtf3vo/LA==',
  salt: '+uzzUKmbAdwkjw8rILhJvZE9dOfz2ecF5Gtf7yNkyyE=',
};

test('encryptor:decrypt encrypted data', async ({ page }) => {
  const password = 'a sample passw0rd';
  const expectedData = { foo: 'data to encrypt' };

  const decryptedData = await page.evaluate(
    async (args) =>
      await window.encryptor.decrypt(
        args.password,
        JSON.stringify(args.sampleEncryptedData),
      ),
    { sampleEncryptedData, password },
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
          JSON.stringify(args.sampleEncryptedData),
        ),
      { sampleEncryptedData, wrongPassword },
    ),
  ).rejects.toThrow('Incorrect password');
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
  expect(Object.keys(encryptedData).sort()).toStrictEqual(['data', 'iv']);

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
  expect(Object.keys(encryptedData).sort()).toStrictEqual(['data', 'iv']);

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
  const encryptedPayload = { data: encryptedData.data, iv: encryptedData.iv };

  const decryptedData = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.keyFromPassword(
        args.password,
        args.salt,
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
  const encryptedPayload = { data: encryptedData.data, iv: encryptedData.iv };

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
    data: sampleEncryptedData.data,
    iv: sampleEncryptedData.iv,
  };
  const { salt } = sampleEncryptedData;

  const decryptedData = await page.evaluate(
    async (args) => {
      const key = await window.encryptor.keyFromPassword(
        args.password,
        args.salt,
      );
      return await window.encryptor.decryptWithKey(key, args.encryptedPayload);
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
    data: sampleEncryptedData.data,
    iv: sampleEncryptedData.iv,
  };
  const { salt } = sampleEncryptedData;

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
