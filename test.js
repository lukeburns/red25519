const test = require('brittle')
const b4a = require('b4a')
const crypto = require('./')

test('derive public key matches normalize', function (t) {
  const publicKey = b4a.from('00e1de09b98d1052af8f3fda02a0a7df9abaf7d5c6d1ac53528d5cb7c7e5678b', 'hex')
  const secretKey = b4a.from('b34874c2fb5f6e3fc71b1e63356104d5db679a89c2378cf314eb8f92b1f9617300e1de09b98d1052af8f3fda02a0a7df9abaf7d5c6d1ac53528d5cb7c7e5678b', 'hex')
  const normalizedPublicKey = crypto.normalizePublicKey(publicKey)
  const normalizedKeyPair = crypto.normalize(secretKey)
  console.log(normalizedPublicKey.toString('hex'))
  console.log(normalizedKeyPair.publicKey.toString('hex'))
  t.ok(b4a.equals(normalizedPublicKey, normalizedKeyPair.publicKey))
})

test('normalize', function (t) {
  const secret = b4a.from('fe09664f812e27e43982ad43f69e68b99665733a3d65cb6a0ba853d3761aafa8e1e716536d45f8f29e8f3ae79a81e44d6a7f7d5dde58187663e33e352e2285f8', 'hex')
  const keyPair = crypto.normalize(secret)
  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
  t.is(keyPair.publicKey.buffer.byteLength, 96, 'small slab')
  t.is(keyPair.publicKey.buffer, keyPair.secretKey.buffer, 'public and seret key share the same slab')
  t.ok(crypto.validateKeyPair({ publicKey: keyPair.publicKey, secretKey: keyPair.secretKey }))
})

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
  const namespace = 'hello world'
  const derivedKeyPair = crypto.deriveKeyPair(keyPair.secretKey, namespace)
  t.ok(crypto.validateKeyPair({ publicKey: derivedKeyPair.publicKey, secretKey: derivedKeyPair.secretKey }))

  const derivedPublicKey = crypto.derivePublicKey(keyPair.publicKey, namespace)
  t.ok(b4a.equals(derivedPublicKey, derivedKeyPair.publicKey))

  const namespaceHex = '68656c6c6f20776f726c64'
  const derivedHexPair = crypto.deriveKeyPair(keyPair.secretKey, namespaceHex, 'hex')
  const derivedHexPair2 = crypto.deriveKeyPair(keyPair.secretKey, namespaceHex, { encoding: 'hex' })
  t.ok(b4a.equals(derivedHexPair.publicKey, derivedHexPair2.publicKey))
  const derivedHexPublicKey = crypto.derivePublicKey(keyPair.publicKey, namespaceHex, 'hex')
  t.ok(b4a.equals(derivedHexPublicKey, derivedHexPair.publicKey))
})

test('derive shared secret', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()
  const sharedSecret1 = crypto.deriveSharedSecret(keyPair1.secretKey, keyPair2.publicKey)
  const sharedSecret2 = crypto.deriveSharedSecret(keyPair2.secretKey, keyPair1.publicKey)
  t.ok(b4a.equals(sharedSecret1, sharedSecret2))
})

test('sign helpers and constants', function (t) {
  t.is(crypto.PUBLIC_KEY_LENGTH, 32)
  t.is(crypto.PRIVATE_KEY_LENGTH, 32)
  t.is(crypto.SECRET_KEY_LENGTH, 64)
  t.is(crypto.SIGNATURE_LENGTH, 64)
  t.is(crypto.SHARED_SECRET_LENGTH, 32)

  const keyPair = crypto.keyPair()
  const message = b4a.from('helpers')
  const sig = crypto.sign(message, keyPair.secretKey)
  t.is(sig.length, crypto.SIGNATURE_LENGTH)
  t.ok(b4a.equals(sig, crypto.signDetached(message, keyPair.secretKey)))
  t.ok(b4a.equals(sig, crypto.signKeyPair(keyPair, message)))
})

test('normalize is idempotent for public keys', function (t) {
  const keyPair = crypto.keyPair()
  const normalizedPublicKey = crypto.normalizePublicKey(keyPair.publicKey)
  const normalizedPublicKey2 = crypto.normalizePublicKey(normalizedPublicKey)
  t.ok(b4a.equals(normalizedPublicKey, normalizedPublicKey2))
})