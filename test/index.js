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

QUnit.test('encryptor:encrypt & decrypt', function (assert) {
  const done = assert.async();

  const password = 'a sample passw0rd';
  const data = { foo: 'data to encrypt' };

  encryptor
    .encrypt(password, data)
    .then(function (encryptedStr) {
      assert.equal(typeof encryptedStr, 'string', 'returns a string');
      return encryptor.decrypt(password, encryptedStr);
    })
    .then(function (decryptedObj) {
      assert.deepEqual(decryptedObj, data, 'decrypted what was encrypted');
      done();
    })
    .catch(function (reason) {
      console.error(reason);
      assert.ifError(reason, 'threw an error');
      done(reason);
    });
});

QUnit.test(
  'encryptor:encrypt & decrypt with wrong password',
  function (assert) {
    const done = assert.async();

    const password = 'a sample passw0rd';
    const wrongPassword = 'a wrong password';
    const data = { foo: 'data to encrypt' };

    encryptor
      .encrypt(password, data)
      .then(function (encryptedStr) {
        assert.equal(typeof encryptedStr, 'string', 'returns a string');
        return encryptor.decrypt(wrongPassword, encryptedStr);
      })
      .then(function (decryptedObj) {
        assert.equal(!decryptedObj, true, 'Wrong password should not decrypt');
        done();
      })
      .catch(function (_error) {
        done();
      });
  },
);
