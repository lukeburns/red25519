const { ed25519, ristretto255, ristretto255_hasher } = require('@noble/curves/ed25519.js')
const { bytesToNumberLE } = require('@noble/curves/utils.js')
const { mod, invert, Field } = require('@noble/curves/abstract/modular.js');
const { sha512 } = require('@noble/hashes/sha2.js')
const { concatBytes, randomBytes } = require('@noble/hashes/utils.js')
const b4a = require('b4a')

function modN_LE(hash) {
    return ed25519.Point.Fn.create(bytesToNumberLE(hash))
}

function hashDomainToScalar(...msgs) {
    return modN_LE(sha512(concatBytes(...msgs)))
}

const L = ed25519.Point.Fn.ORDER;
const INV_8 = mod(invert(8n, L), L);

function normalize(point) {
  if (point.ep) point = point.ep
  return point.multiply(8n).multiply(INV_8)
}

exports.upgradeKeyPair = function (ed25519SecretKey) {
  if (ed25519SecretKey && ed25519SecretKey.secretKey) {
    ed25519SecretKey = ed25519SecretKey.secretKey
  }

  const seed = ed25519SecretKey.length === 64 ? ed25519SecretKey.subarray(0, 32) : ed25519SecretKey
  
  const hash = sha512(seed)
  const h_L = hash.subarray(0, 32)
  
  const clamped = new Uint8Array(h_L)
  clamped[0] &= 248
  clamped[31] &= 127
  clamped[31] |= 64
  
  const privateScalar = ristretto255.Point.Fn.create(bytesToNumberLE(clamped))
  const privateKey = b4a.from(ristretto255.Point.Fn.toBytes(privateScalar))
  
  const ristrettoPoint = ristretto255.Point.BASE.multiply(privateScalar)
  const ed25519Point = normalize(ristrettoPoint)
  const ed25519PublicKey = ed25519Point.toBytes()

  const slab = b4a.allocUnsafeSlow(32 + 64)
  const publicKeyBuffer = slab.subarray(0, 32)
  const secretKeyBuffer = slab.subarray(32)
  publicKeyBuffer.set(ed25519PublicKey)
  secretKeyBuffer.set(privateKey, 0, 32)
  secretKeyBuffer.set(publicKeyBuffer, 32, 32)

  return {
    publicKey: publicKeyBuffer, // edwards curve public key
    secretKey: secretKeyBuffer // ristretto255 private key
  }
}

exports.upgrade = exports.upgradeKeyPair

exports.upgradePublicKey = function (publicKey) {
  const ed25519Point = ed25519.Point.fromBytes(publicKey)
  const ristrettoPoint = new ristretto255.Point(ed25519Point)
  const ed25519Point2 = normalize(ristrettoPoint)
  const upgradedPublicKey = ed25519Point2.toBytes()
  return b4a.from(upgradedPublicKey)
}

exports.normalize = exports.upgradePublicKey

exports.keyPair = function (seed) {
  let privateKey

  if (b4a.isBuffer(seed) || typeof seed === 'string') {
    const scalar = ristretto255_hasher.hashToScalar(seed)
    privateKey = b4a.from(ristretto255.Point.Fn.toBytes(scalar))
  } else {
    const scalar = ristretto255_hasher.hashToScalar(randomBytes(32))
    privateKey = b4a.from(ristretto255.Point.Fn.toBytes(scalar))
  }

  const privateKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
  const ristrettoPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
  const ed25519Point = normalize(ristrettoPoint)
  const ed25519PublicKey = ed25519Point.toBytes()

  const slab = b4a.allocUnsafeSlow(32 + 64)
  const publicKeyBuffer = slab.subarray(0, 32)
  const secretKeyBuffer = slab.subarray(32)
  publicKeyBuffer.set(ed25519PublicKey)
  secretKeyBuffer.set(privateKey, 0, 32)
  secretKeyBuffer.set(publicKeyBuffer, 32, 32)

  return {
    publicKey: publicKeyBuffer,
    secretKey: secretKeyBuffer
  }
}

exports.deriveKeyPair = function (secretKey, bytes) {
  const privateKey = secretKey.subarray(0, 32)
  const privateScalar = ristretto255.Point.Fn.fromBytes(privateKey)
  
  let derivedScalar
  if (!bytes || bytes.byteLength === 0) {
    derivedScalar = privateScalar
  } else {
    const bytesScalar = ristretto255_hasher.hashToScalar(bytes)
    derivedScalar = ristretto255.Point.Fn.create(privateScalar * bytesScalar)
  }
  
  const derivedBytes = ristretto255.Point.Fn.toBytes(derivedScalar)
  const ristrettoPoint = ristretto255.Point.BASE.multiply(derivedScalar)
  const ed25519Point = normalize(ristrettoPoint)
  const ed25519PublicKey = ed25519Point.toBytes()

  const slab = b4a.allocUnsafeSlow(32 + 64)
  const publicKeyBuffer = slab.subarray(0, 32)
  const secretKeyBuffer = slab.subarray(32)
  publicKeyBuffer.set(ed25519PublicKey)
  secretKeyBuffer.set(derivedBytes, 0, 32)
  secretKeyBuffer.set(publicKeyBuffer, 32, 32)

  return {
    publicKey: publicKeyBuffer,
    secretKey: secretKeyBuffer
  }
}

exports.derivePublicKey = function (publicKey, bytes) {
  const ed25519Point = ed25519.Point.fromBytes(publicKey)
  const ristrettoPoint = new ristretto255.Point(ed25519Point)
  const bytesScalar = ristretto255_hasher.hashToScalar(bytes)
  const derivedPoint = ristrettoPoint.multiply(bytesScalar)
  const ed25519DerivedPoint = normalize(derivedPoint)
  return b4a.from(ed25519DerivedPoint.toBytes())
}

exports.validateKeyPair = function (keyPair) {
  try {
    // Extract the private key from the first 32 bytes of the secret key
    const privateKey = keyPair.secretKey.subarray(0, 32)

    const privateKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
    const ristrettoPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
    const ed25519Point = normalize(ristrettoPoint)
    const ed25519PublicKey = ed25519Point.toBytes()
    
    return b4a.equals(ed25519PublicKey, keyPair.publicKey)
  } catch (e) {
    return false
  }
}

exports.deriveSharedSecret = function (secretKey, publicKey) {
  const privateKey = secretKey.subarray(0, 32)
  const privateScalar = ristretto255.Point.Fn.fromBytes(privateKey)
  const ed25519Point = ed25519.Point.fromBytes(publicKey)
  if (ed25519Point.isSmallOrder()) throw new Error('invalid DH: small public key')
  const ristrettoPoint = new ristretto255.Point(ed25519Point)
  const sharedPoint = ristrettoPoint.multiply(privateScalar)
  const normalizedPoint = normalize(sharedPoint)
  if (normalizedPoint.is0()) throw new Error('invalid DH: identity shared secret')
  return b4a.from(normalizedPoint.toBytes())
}

exports.sign = function (message, secretKey) {
  const privateKey = secretKey.subarray(0, 32)
  const publicKey = secretKey.subarray(32, 64)
  const s = ed25519.Point.Fn.create(bytesToNumberLE(privateKey))
  const r = hashDomainToScalar(privateKey, message)
  const R = ed25519.Point.BASE.multiply(r).toBytes()
  const k = hashDomainToScalar(R, publicKey, message)
  const S = ed25519.Point.Fn.create(r + k * s)
  if (!ed25519.Point.Fn.isValid(S)) throw new Error('sign failed: invalid s') // 0 <= s < L
  return concatBytes(R, ed25519.Point.Fn.toBytes(S))
}

exports.verify = function (message, signature, publicKey) {
  return ed25519.verify(signature, message, publicKey)
}

exports.randomBytes = randomBytes