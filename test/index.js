const encryptor = require('../dist');

QUnit.module('encryptor');

QUnit.test('encryptor:serializeBufferForStorage', function (assert) {
  assert.expect(1);
  const buf = Buffer.alloc(2);
  buf[0] = 16;
  buf[1] = 1;

  const output = encryptor.serializeBufferForStorage(buf);

  const expect = '0x1001';
  assert.equal(expect, output);
});

QUnit.test('encryptor:serializeBufferFromStorage', function (assert) {
  assert.expect(2);
  const input = '0x1001';
  const output = encryptor.serializeBufferFromStorage(input);

  assert.equal(output[0], 16);
  assert.equal(output[1], 1);
});

QUnit.test(
  'encryptor:generateSalt generates 32 byte Base64-encoded string by default',
  function (assert) {
    assert.expect(2);

    const salt = encryptor.generateSalt();
    assert.equal(salt.length, 44, 'should generate salt 44 characters long');
    const decodedSalt = atob(salt);
    assert.equal(
      decodedSalt.length,
      32,
      'should decode salt 32 characters long',
    );
  },
);

QUnit.test(
  'encryptor:generateSalt generates 32 byte Base64-encoded string',
  function (assert) {
    assert.expect(2);

    const salt = encryptor.generateSalt(32);
    assert.equal(salt.length, 44, 'should generate salt 44 characters long');
    const decodedSalt = atob(salt);
    assert.equal(
      decodedSalt.length,
      32,
      'should decode salt 32 characters long',
    );
  },
);

QUnit.test(
  'encryptor:generateSalt generates 16 byte Base64-encoded string',
  function (assert) {
    assert.expect(2);

    const salt = encryptor.generateSalt(16);
    assert.equal(salt.length, 24, 'should generate salt 24 characters long');
    const decodedSalt = atob(salt);
    assert.equal(
      decodedSalt.length,
      16,
      'should decode salt 16 characters long',
    );
  },
);

QUnit.test(
  'encryptor:generateSalt generates 64 byte Base64-encoded string',
  function (assert) {
    assert.expect(2);

    const salt = encryptor.generateSalt(64);
    assert.equal(salt.length, 88, 'should generate salt 88 characters long');
    const decodedSalt = atob(salt);
    assert.equal(
      decodedSalt.length,
      64,
      'should decode salt 64 characters long',
    );
  },
);

QUnit.test('encryptor:encrypt & decrypt', async function (assert) {
  const done = assert.async();

  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  try {
    const encryptedStr = await encryptor.encrypt(password, data);
    assert.equal(typeof encryptedStr, 'string', 'returns a string');

    const decryptedObj = await encryptor.decrypt(password, encryptedStr);
    assert.deepEqual(decryptedObj, data, 'decrypted what was encrypted');
    done();
  } catch (error) {
    assert.false(error, 'should be unreachable');
    done();
  }
});

QUnit.test(
  'encryptor:encrypt & decrypt with wrong password',
  async function (assert) {
    const done = assert.async();

    const password = 'a sample passw0rd';
    const wrongPassword = 'a wrong password';
    const data = { foo: 'data to encrypt' };

    try {
      const encryptedStr = await encryptor.encrypt(password, data);
      assert.equal(typeof encryptedStr, 'string', 'returns a string');
      await encryptor.decrypt(wrongPassword, encryptedStr);
      assert.false(true, 'should be unreachable');
    } catch (error) {
      assert.equal(error.message, 'Incorrect password');
      done();
    }
  },
);

/**
 * This is the encrypted object `{ foo: 'data to encrypt' }`, which was
 * encrypted using v2.0.3 of this library with the password
 * `a sample passw0rd`. This should be left unmodified, as it's used to test
 * that decrypting older encrypted data continues to work.
 */
const encryptedData = {
  data: 'bfCvija6QfwqARmHsKT7ZR0GHi8yjz7iVEZodRVx3xI2yzFHwq7+B/U=',
  iv: 'N9s46G5sp37A7wtf3vo/LA==',
  salt: '+uzzUKmbAdwkjw8rILhJvZE9dOfz2ecF5Gtf7yNkyyE=',
};

QUnit.test('encryptor:decrypt encrypted data', async function (assert) {
  const done = assert.async();

  const password = 'a sample passw0rd';
  const expectedData = { foo: 'data to encrypt' };

  try {
    const decryptedObj = await encryptor.decrypt(
      password,
      JSON.stringify(encryptedData),
    );
    assert.deepEqual(
      decryptedObj,
      expectedData,
      'Expected data should be decrypted',
    );
    done();
  } catch (error) {
    assert.notOk(error, 'should be unreachable');
    done();
  }
});

QUnit.test(
  'encryptor:decrypt encrypted data using wrong password',
  async function (assert) {
    const done = assert.async();

    const wrongPassword = 'a wrong password';

    try {
      await encryptor.decrypt(wrongPassword, JSON.stringify(encryptedData));
      assert.notOk(true, 'should be unreachable');
      done();
    } catch (error) {
      assert.equal(error.message, 'Incorrect password');
      done();
    }
  },
);

QUnit.test('encryptor:encrypt using key then decrypt', async function (assert) {
  const done = assert.async();

  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };
  const salt = encryptor.generateSalt();

  try {
    const key = await encryptor.keyFromPassword(password, salt);
    const encryptedObj = await encryptor.encryptWithKey(key, data);

    assert.deepEqual(
      Object.keys(encryptedObj).sort(),
      ['data', 'iv'],
      'returns expected shape',
    );

    const encryptedStr = JSON.stringify(
      Object.assign({}, encryptedObj, { salt }),
    );
    const decryptedObj = await encryptor.decrypt(password, encryptedStr);

    assert.deepEqual(decryptedObj, data, 'decrypted what was encrypted');
    done();
  } catch (error) {
    assert.notOk(error, 'should be unreachable');
    done();
  }
});

QUnit.test(
  'encryptor:encrypt using key then decrypt using wrong password',
  async function (assert) {
    const done = assert.async();

    const password = 'a sample passw0rd';
    const wrongPassword = 'a wrong password';
    const data = { foo: 'data to encrypt' };
    const salt = encryptor.generateSalt();

    try {
      const key = await encryptor.keyFromPassword(password, salt);
      const encryptedObj = await encryptor.encryptWithKey(key, data);

      assert.deepEqual(
        Object.keys(encryptedObj).sort(),
        ['data', 'iv'],
        'returns expected shape',
      );

      const encryptedStr = JSON.stringify(
        Object.assign({}, encryptedObj, { salt }),
      );
      await encryptor.decrypt(wrongPassword, encryptedStr);
      assert.notOk(true, 'should be unreachable');
      done();
    } catch (error) {
      assert.equal(error.message, 'Incorrect password');
      done();
    }
  },
);

QUnit.test('encryptor:encrypt then decrypt using key', async function (assert) {
  const done = assert.async();

  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  try {
    const encryptedStr = await encryptor.encrypt(password, data);

    assert.equal(typeof encryptedStr, 'string', 'returns a string');
    const encryptedObj = JSON.parse(encryptedStr);
    const { salt } = encryptedObj;
    const encryptedPayload = { data: encryptedObj.data, iv: encryptedObj.iv };

    const key = await encryptor.keyFromPassword(password, salt);
    const decryptedObj = await encryptor.decryptWithKey(key, encryptedPayload);

    assert.deepEqual(decryptedObj, data, 'decrypted what was encrypted');
    done();
  } catch (error) {
    assert.notOk(error, 'should be unreachable');
    done();
  }
});

QUnit.test(
  'encryptor:encrypt then decrypt using key derived from wrong password',
  async function (assert) {
    const done = assert.async();

    const password = 'a sample passw0rd';
    const wrongPassword = 'a wrong password';
    const data = { foo: 'data to encrypt' };

    try {
      const encryptedStr = await encryptor.encrypt(password, data);

      assert.equal(typeof encryptedStr, 'string', 'returns a string');
      const encryptedObj = JSON.parse(encryptedStr);
      const { salt } = encryptedObj;
      const encryptedPayload = { data: encryptedObj.data, iv: encryptedObj.iv };

      const key = await encryptor.keyFromPassword(wrongPassword, salt);
      await encryptor.decryptWithKey(key, encryptedPayload);
      assert.notOk(true, 'should be unreachable');
      done();
    } catch (error) {
      assert.equal(error.message, 'Incorrect password');
      done();
    }
  },
);

QUnit.test(
  'encryptor:decrypt encrypted data using key',
  async function (assert) {
    const done = assert.async();

    const password = 'a sample passw0rd';
    const expectedData = { foo: 'data to encrypt' };
    const encryptedPayload = { data: encryptedData.data, iv: encryptedData.iv };

    try {
      const key = await encryptor.keyFromPassword(password, encryptedData.salt);
      const decryptedObj = await encryptor.decryptWithKey(
        key,
        encryptedPayload,
      );
      assert.deepEqual(
        decryptedObj,
        expectedData,
        'Expected data should be decrypted',
      );
      done();
    } catch (error) {
      assert.notOk(error, 'should be unreachable');
      done();
    }
  },
);

QUnit.test(
  'encryptor:decrypt encrypted data using key derived from wrong password',
  async function (assert) {
    const done = assert.async();

    const wrongPassword = 'a wrong password';
    const encryptedPayload = { data: encryptedData.data, iv: encryptedData.iv };

    try {
      const key = await encryptor.keyFromPassword(
        wrongPassword,
        encryptedData.salt,
      );
      await encryptor.decryptWithKey(key, encryptedPayload);
      assert.notOk(true, 'should be unreachable');
      done();
    } catch (error) {
      assert.equal(error.message, 'Incorrect password');
      done();
    }
  },
);
