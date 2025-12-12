const test = require('brittle')
const b4a = require('b4a')
const crypto = require('./')
const sodium = require('sodium-universal')
const { ed25519 } = require('@noble/curves/ed25519.js')
const { generateKeyPair, dh } = require('noise-curve-ed')

test('key pair generation', function (t) {
  const keyPair = crypto.keyPair()
  
  t.is(keyPair.publicKey.length, 32, 'public key is 32 bytes')
  t.is(keyPair.secretKey.length, 64, 'secret key is 64 bytes')
  t.ok(crypto.validateKeyPair(keyPair), 'generated keypair is valid')
})

test('key pair validation', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()
  
  t.ok(crypto.validateKeyPair(keyPair1), 'keypair validates itself')
  t.absent(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair2.secretKey }), 'mismatched keypair fails validation')
})

test('normalize produces torsion-free representative', function (t) {
  const { ristretto255, ed25519 } = require('@noble/curves/ed25519.js')
  
  // Generate multiple keypairs to find one with non-torsion-free canonical form
  for (let i = 0; i < 50; i++) {
    const { publicKey, secretKey } = crypto.keyPair()
    const point = ed25519.Point.fromBytes(publicKey)
    
    if (!point.isTorsionFree()) {
      // Get the ristretto point
      const ristrettoScalar = ristretto255.Point.Fn.fromBytes(secretKey.subarray(0, 32))
      const ristrettoPoint = ristretto255.Point.BASE.multiply(ristrettoScalar)
      
      // Normalize should produce torsion-free representative
      const normalized = crypto.normalize(publicKey)
      const normalizedPoint = ed25519.Point.fromBytes(normalized)
      
      t.ok(normalizedPoint.isTorsionFree(), 'normalized point is torsion-free')
      t.ok(ristrettoPoint.ep.equals(normalizedPoint), 'normalized point equals ristretto internal representation')
      return
    }
  }
  
  t.pass('all tested keypairs had torsion-free canonical forms')
})

test('normalize is idempotent', function (t) {
  const { publicKey } = crypto.keyPair()
  const normalized1 = crypto.normalize(publicKey)
  const normalized2 = crypto.normalize(normalized1)
  
  t.ok(b4a.equals(normalized1, normalized2), 'normalize is idempotent')
})

test('derive public key matches upgrade', function (t) {
  const publicKey = b4a.from('00e1de09b98d1052af8f3fda02a0a7df9abaf7d5c6d1ac53528d5cb7c7e5678b', 'hex')
  const secretKey = b4a.from('b34874c2fb5f6e3fc71b1e63356104d5db679a89c2378cf314eb8f92b1f9617300e1de09b98d1052af8f3fda02a0a7df9abaf7d5c6d1ac53528d5cb7c7e5678b', 'hex')
  const upgradedPublicKey = crypto.upgradePublicKey(publicKey)
  const upgradedKeyPair = crypto.upgrade(secretKey)
  t.ok(b4a.equals(upgradedPublicKey, upgradedKeyPair.publicKey))
})

test('sign and verify', function (t) {
  const keyPair = crypto.keyPair()
  const message = b4a.from('hello world')
  
  const sig = crypto.sign(message, keyPair.secretKey)
  t.is(sig.length, 64, 'signature is 64 bytes')
  t.ok(crypto.verify(message, sig, keyPair.publicKey), 'signature verifies')
  t.absent(crypto.verify(message, b4a.alloc(64), keyPair.publicKey), 'invalid signature fails')
  t.absent(crypto.verify(b4a.from('different'), sig, keyPair.publicKey), 'wrong message fails')
})

test('derive key pair', function (t) {
  const keyPair = crypto.keyPair()
  const namespace = b4a.from('hello world')
  const derivedKeyPair = crypto.deriveKeyPair(keyPair.secretKey, namespace)
  
  t.ok(crypto.validateKeyPair(derivedKeyPair), 'derived keypair is valid')
  t.absent(b4a.equals(derivedKeyPair.publicKey, keyPair.publicKey), 'derived public key differs')
  t.absent(b4a.equals(derivedKeyPair.secretKey, keyPair.secretKey), 'derived secret key differs')
  
  const derivedPublicKey = crypto.derivePublicKey(keyPair.publicKey, namespace)
  t.ok(b4a.equals(derivedPublicKey, derivedKeyPair.publicKey), 'derivePublicKey matches deriveKeyPair')
})

test('derive key pair with no bytes returns associated keypair', function (t) {
  const keyPair = crypto.keyPair()
  
  const associatedKeyPair = crypto.deriveKeyPair(keyPair.secretKey)
  t.ok(crypto.validateKeyPair(associatedKeyPair), 'derived keypair is valid')
  t.ok(b4a.equals(associatedKeyPair.publicKey, keyPair.publicKey), 'derived public key matches')
  t.ok(b4a.equals(associatedKeyPair.secretKey, keyPair.secretKey), 'derived secret key matches')
  
  const associatedKeyPair2 = crypto.deriveKeyPair(keyPair.secretKey, b4a.alloc(0))
  t.ok(b4a.equals(associatedKeyPair2.publicKey, keyPair.publicKey), 'derived public key with empty bytes matches')
  t.ok(b4a.equals(associatedKeyPair2.secretKey, keyPair.secretKey), 'derived secret key with empty bytes matches')
})

test('derive shared secret', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()
  const sharedSecret1 = crypto.deriveSharedSecret(keyPair1.secretKey, keyPair2.publicKey)
  const sharedSecret2 = crypto.deriveSharedSecret(keyPair2.secretKey, keyPair1.publicKey)
  
  t.ok(b4a.equals(sharedSecret1, sharedSecret2), 'shared secrets match')
  t.is(sharedSecret1.length, 32, 'shared secret is 32 bytes')
})

test('derive shared secret with identity point throws', function (t) {
  const keyPair = crypto.keyPair()
  const identityPublicKey = ed25519.Point.ZERO.toBytes()
  
  t.exception(() => {
    crypto.deriveSharedSecret(keyPair.secretKey, identityPublicKey)
  }, 'deriving shared secret with identity point throws')
})

test('public key differs from s*B by torsion only', function (t) {
  for (let i = 0; i < 50; i++) {
    const { publicKey, secretKey } = crypto.keyPair()

    const privateKey = secretKey.subarray(0, 32)
    const s = ed25519.Point.Fn.fromBytes(privateKey)

    const A = ed25519.Point.fromBytes(publicKey)
    const SB = ed25519.Point.BASE.multiply(s)

    const D = A.subtract(SB) // D = A - sB

    const isZero = D.equals(ed25519.Point.ZERO)
    const isTorsion = D.multiply(8n).equals(ed25519.Point.ZERO)

    if (!isZero) {
      t.ok(isTorsion, 'difference A - sB should be 8-torsion')
      return
    }
  }
  t.pass('all tested keypairs had A = s*B')
})

test('upgrade', function (t) {
  const secret = b4a.from('fe09664f812e27e43982ad43f69e68b99665733a3d65cb6a0ba853d3761aafa8e1e716536d45f8f29e8f3ae79a81e44d6a7f7d5dde58187663e33e352e2285f8', 'hex')
  const keyPair = crypto.upgrade(secret)
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
  const namespace = b4a.from('hello world')
  const derivedKeyPair = crypto.deriveKeyPair(keyPair.secretKey, namespace)
  t.ok(crypto.validateKeyPair({ publicKey: derivedKeyPair.publicKey, secretKey: derivedKeyPair.secretKey }))

  const derivedPublicKey = crypto.derivePublicKey(keyPair.publicKey, namespace)
  t.ok(b4a.equals(derivedPublicKey, derivedKeyPair.publicKey))
})

test('derive key pair with no bytes returns associated keypair', function (t) {
  const keyPair = crypto.keyPair()
  
  const associatedKeyPair = crypto.deriveKeyPair(keyPair.secretKey)
  t.ok(crypto.validateKeyPair({ publicKey: associatedKeyPair.publicKey, secretKey: associatedKeyPair.secretKey }))
  t.ok(b4a.equals(associatedKeyPair.publicKey, keyPair.publicKey))
  t.ok(b4a.equals(associatedKeyPair.secretKey, keyPair.secretKey))
  
  const associatedKeyPair2 = crypto.deriveKeyPair(keyPair.secretKey, b4a.alloc(0))
  t.ok(b4a.equals(associatedKeyPair2.publicKey, keyPair.publicKey))
  t.ok(b4a.equals(associatedKeyPair2.secretKey, keyPair.secretKey))
  
  const associatedKeyPair3 = crypto.deriveKeyPair(keyPair.secretKey, undefined)
  t.ok(b4a.equals(associatedKeyPair3.publicKey, keyPair.publicKey))
  t.ok(b4a.equals(associatedKeyPair3.secretKey, keyPair.secretKey))
})

test('derive shared secret', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()
  const sharedSecret1 = crypto.deriveSharedSecret(keyPair1.secretKey, keyPair2.publicKey)
  const sharedSecret2 = crypto.deriveSharedSecret(keyPair2.secretKey, keyPair1.publicKey)
  t.ok(b4a.equals(sharedSecret1, sharedSecret2))
})

test('shared secret should agree with ed diffie-hellman', function (t) {
  const alice = crypto.keyPair()
  const bob = generateKeyPair()
  const alicesSharedSecret = crypto.deriveSharedSecret(alice.secretKey, bob.publicKey)
  const bobsSharedSecret = dh(alice.publicKey, bob)

  t.ok(b4a.equals(alicesSharedSecret, bobsSharedSecret))
})

test('should reject bad DH', function (t) {
  const keyPair = crypto.keyPair()
  const identityPublicKey = ed25519.Point.ZERO.toBytes()
  t.exception(() => {
    crypto.deriveSharedSecret(keyPair.secretKey, identityPublicKey)
  }, 'deriving shared secret with identity point throws')
})

test('red25519 sign - sodium verify compatibility', function (t) {
    const keyPair = crypto.keyPair()
    const message = b4a.from(`hello world`)
    
    const signature = crypto.sign(message, keyPair.secretKey)
    t.is(signature.length, 64)
    
    const red25519Verify = crypto.verify(message, signature, keyPair.publicKey)
    t.ok(red25519Verify, `red25519 should verify its own signatures`)
    
    const sodiumVerifyResult = sodium.crypto_sign_verify_detached(signature, message, keyPair.publicKey)
    
    t.ok(sodiumVerifyResult, `sodium should verify red25519 signatures`)
})

test('sodium sign - red25519 verify compatibility', function (t) {
  const publicKey = b4a.allocUnsafe(32)
  const secretKey = b4a.allocUnsafe(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  
  const message = b4a.from('hello world')
  
  const signature = b4a.allocUnsafe(64)
  sodium.crypto_sign_detached(signature, message, secretKey)
  t.is(signature.length, 64)
  
  t.ok(sodium.crypto_sign_verify_detached(signature, message, publicKey), 'sodium should verify its own signatures')
  t.ok(crypto.verify(message, signature, publicKey), 'red25519 should verify sodium signatures')
})
