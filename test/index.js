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
