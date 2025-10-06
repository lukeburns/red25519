const test = require('brittle')
const b4a = require('b4a')
const crypto = require('./')

test('randomBytes', function (t) {
  const buffer = crypto.randomBytes(100)
  t.ok(b4a.isBuffer(buffer))
  t.unlike(crypto.randomBytes(100), buffer)
})

test('key pair', function (t) {
  const keyPair = crypto.keyPair()

  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
  t.is(keyPair.publicKey.buffer.byteLength, 96, 'small slab')
  t.is(keyPair.publicKey.buffer, keyPair.secretKey.buffer, 'public and seret key share the same slab')
})

test('validate key pair', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()

  t.absent(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair2.secretKey }))
  t.ok(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair1.secretKey }))
})

test('sign', function (t) {
  const keyPair = crypto.keyPair()
  const message = b4a.from('hello world')

  const sig = crypto.sign(message, keyPair.secretKey)

  t.is(sig.length, 64)
  t.ok(crypto.verify(message, sig, keyPair.publicKey))
  t.absent(crypto.verify(message, b4a.alloc(64), keyPair.publicKey))
  t.is(sig.buffer.byteLength, 64, 'dedicated slab for signatures')
})

test('derive key pair', function (t) {
  const keyPair = crypto.keyPair()
  const namespace = b4a.from('hello world')
  const derivedKeyPair = crypto.deriveKeyPair(keyPair.secretKey, namespace)
  t.ok(crypto.validateKeyPair({ publicKey: derivedKeyPair.publicKey, secretKey: derivedKeyPair.secretKey }))

  const derivedPublicKey = crypto.derivePublicKey(keyPair.publicKey, namespace)
  t.ok(b4a.equals(derivedPublicKey, derivedKeyPair.publicKey))
})

test('derive shared secret', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()
  const sharedSecret1 = crypto.deriveSharedSecret(keyPair1.secretKey, keyPair2.publicKey)
  const sharedSecret2 = crypto.deriveSharedSecret(keyPair2.secretKey, keyPair1.publicKey)
  t.ok(b4a.equals(sharedSecret1, sharedSecret2))
})