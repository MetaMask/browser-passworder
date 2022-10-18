const encryptor = require('../dist');

describe('encryptor', function () {

  /**
     * This is the encrypted object `{ foo: 'data to encrypt' }`, which was
     * encrypted using v2.0.3 of this library with the password
     * `a sample passw0rd`. This should be left unmodified, as it's used to test
     * that decrypting older encrypted data continues to work.
     */
   const MOCK_ENCRYPTED_DATA = {
    data: 'bfCvija6QfwqARmHsKT7ZR0GHi8yjz7iVEZodRVx3xI2yzFHwq7+B/U=',
    iv: 'N9s46G5sp37A7wtf3vo/LA==',
    salt: '+uzzUKmbAdwkjw8rILhJvZE9dOfz2ecF5Gtf7yNkyyE=',
  };

  describe('serializeBuffer', function () {
    it('encryptor:serializeBufferForStorage', function () {
      const buf = Buffer.alloc(2);
      buf[0] = 16;
      buf[1] = 1;

      const output = encryptor.serializeBufferForStorage(buf);

      const expected = '0x1001';
      expect(output).toBe(expected);
    });

    it('encryptor:serializeBufferFromStorage', function () {
      const input = '0x1001';
      const output = encryptor.serializeBufferFromStorage(input);

      expect(output[0]).toBe(16);
      expect(output[1]).toBe(1);
    });
  });

  describe('generateSalt', function () {
    it('generates 32 byte Base64-encoded string by default', function () {
      const salt = encryptor.generateSalt();
      expect(salt.length).toBe(44);
      const decodedSalt = atob(salt);
      expect(decodedSalt.length).toBe(32);
    });

    it('generates 32 byte Base64-encoded string', function () {
      const salt = encryptor.generateSalt(32);
      expect(salt.length).toBe(44);
      const decodedSalt = atob(salt);
      expect(decodedSalt.length).toBe(32);
    });

    it('generates 16 byte Base64-encoded string', function () {
      const salt = encryptor.generateSalt(16);
      expect(salt.length).toBe(24);
      const decodedSalt = atob(salt);
      expect(decodedSalt.length).toBe(16);
    });

    it('generates 64 byte Base64-encoded string', function () {
      const salt = encryptor.generateSalt(64);
      expect(salt.length).toBe(88);
      const decodedSalt = atob(salt);
      expect(decodedSalt.length).toBe(64);
    });
  });

  describe('encrypt', function () {
    it('encryptor:encrypt & decrypt', async function () {
      const password = 'a sample passw0rd';
      const data = { foo: 'data to encrypt' };

      const encryptedStr = await encryptor.encrypt(password, data);
      expect(typeof encryptedStr).toBe('string');

      const decryptedObj = await encryptor.decrypt(password, encryptedStr);
      expect(decryptedObj).toMatchObject(data);
    });

    it('encryptor:encrypt & decrypt with wrong password', async function () {
      const password = 'a sample passw0rd';
      const wrongPassword = 'a wrong password';
      const data = { foo: 'data to encrypt' };

      try {
        const encryptedStr = await encryptor.encrypt(password, data);
        expect(typeof encryptedStr).toBe('string');
        await encryptor.decrypt(wrongPassword, encryptedStr);
      } catch (error) {
        expect(error.message).toBe('Incorrect password');
      }
    });
  });

  describe('decrypt', function () {
    it('encryptor:decrypt encrypted data', async function () {
      const password = 'a sample passw0rd';
      const expectedData = { foo: 'data to encrypt' };

      const decryptedObj = await encryptor.decrypt(
        password,
        JSON.stringify(MOCK_ENCRYPTED_DATA),
      );
      expect(decryptedObj).toMatchObject(expectedData);
    });

    it('encryptor:decrypt encrypted data using wrong password', async function () {
      const wrongPassword = 'a wrong password';

      try {
        await encryptor.decrypt(wrongPassword, JSON.stringify(MOCK_ENCRYPTED_DATA));
      } catch (error) {
        expect(error.message).toBe('Incorrect password');
      }
    });
  });

  describe('encryptWithKey', function () {
    it('encryptor:encrypt using key then decrypt', async function () {
      const password = 'a sample passw0rd';
      const data = { foo: 'data to encrypt' };
      const salt = encryptor.generateSalt();

      const key = await encryptor.keyFromPassword(password, salt);
      const encryptedObj = await encryptor.encryptWithKey(key, data);

      expect(Object.keys(encryptedObj).sort()).toMatchObject(['data', 'iv']);

      const encryptedStr = JSON.stringify(
        Object.assign({}, encryptedObj, { salt }),
      );
      const decryptedObj = await encryptor.decrypt(password, encryptedStr);

      expect(decryptedObj).toMatchObject(data);
    });

    it('encryptor:encrypt using key then decrypt using wrong password', async function () {
      const password = 'a sample passw0rd';
      const wrongPassword = 'a wrong password';
      const data = { foo: 'data to encrypt' };
      const salt = encryptor.generateSalt();

      try {
        const key = await encryptor.keyFromPassword(password, salt);
        const encryptedObj = await encryptor.encryptWithKey(key, data);

        expect(Object.keys(encryptedObj).sort()).toMatchObject(['data', 'iv']);

        const encryptedStr = JSON.stringify(
          Object.assign({}, encryptedObj, { salt }),
        );
        await encryptor.decrypt(wrongPassword, encryptedStr);
      } catch (error) {
        expect(error.message).toBe('Incorrect password');
      }
    });
  });

  describe('decryptWithKey', function () {
    it('encryptor:encrypt then decrypt using key', async function () {
      const password = 'a sample passw0rd';
      const data = { foo: 'data to encrypt' };

      const encryptedStr = await encryptor.encrypt(password, data);

      expect(typeof encryptedStr).toBe('string');
      const encryptedObj = JSON.parse(encryptedStr);
      const { salt } = encryptedObj;
      const encryptedPayload = { data: encryptedObj.data, iv: encryptedObj.iv };

      const key = await encryptor.keyFromPassword(password, salt);
      const decryptedObj = await encryptor.decryptWithKey(
        key,
        encryptedPayload,
      );

      expect(decryptedObj).toMatchObject(data);
    });

    it('encryptor:encrypt then decrypt using key derived from wrong password', async function () {
      const password = 'a sample passw0rd';
      const wrongPassword = 'a wrong password';
      const data = { foo: 'data to encrypt' };

      try {
        const encryptedStr = await encryptor.encrypt(password, data);

        expect(typeof encryptedStr).toBe('string');
        const encryptedObj = JSON.parse(encryptedStr);
        const { salt } = encryptedObj;
        const encryptedPayload = {
          data: encryptedObj.data,
          iv: encryptedObj.iv,
        };

        const key = await encryptor.keyFromPassword(wrongPassword, salt);
        await encryptor.decryptWithKey(key, encryptedPayload);
      } catch (error) {
        expect(error.message).toBe('Incorrect password');
      }
    });

    it('encryptor:decrypt encrypted data using key', async function () {
      const password = 'a sample passw0rd';
      const expectedData = { foo: 'data to encrypt' };
      const encryptedPayload = {
        data: MOCK_ENCRYPTED_DATA.data,
        iv: MOCK_ENCRYPTED_DATA.iv,
      };

      const key = await encryptor.keyFromPassword(password, MOCK_ENCRYPTED_DATA.salt);
      const decryptedObj = await encryptor.decryptWithKey(
        key,
        encryptedPayload,
      );
      expect(decryptedObj).toMatchObject(expectedData);
    });

    it('encryptor:decrypt encrypted data using key derived from wrong password', async function () {
      const wrongPassword = 'a wrong password';
      const encryptedPayload = {
        data: MOCK_ENCRYPTED_DATA.data,
        iv: MOCK_ENCRYPTED_DATA.iv,
      };

      try {
        const key = await encryptor.keyFromPassword(
          wrongPassword,
          MOCK_ENCRYPTED_DATA.salt,
        );
        await encryptor.decryptWithKey(key, encryptedPayload);
      } catch (error) {
        expect(error.message).toBe('Incorrect password');
      }
    });
  });
});
