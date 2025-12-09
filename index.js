const { ed25519, ristretto255, ristretto255_hasher } = require('@noble/curves/ed25519.js')
const { bytesToNumberLE } = require('@noble/curves/utils.js')
const { sha512 } = require('@noble/hashes/sha2.js')
const { concatBytes, randomBytes } = require('@noble/hashes/utils.js')
const b4a = require('b4a')

function modN_LE(hash) {
    return ed25519.Point.Fn.create(bytesToNumberLE(hash)) // Not Fn.fromBytes: it has length limit
}

function hashDomainToScalar(...msgs) {
    return modN_LE(sha512(concatBytes(...msgs)))
}

function normalize(ristrettoPoint) {
  const ristrettoPointBytes = ristrettoPoint.toBytes()
  const ristrettoPointFromBytes = ristretto255.Point.fromBytes(ristrettoPointBytes)
  return new ed25519.Point(
    ristrettoPointFromBytes.ep.X,
    ristrettoPointFromBytes.ep.Y,
    ristrettoPointFromBytes.ep.Z,
    ristrettoPointFromBytes.ep.T
  )
}

exports.upgrade = function (ed25519SecretKey) {
  // upgrade ed25519 secret key to ristretto255 key pair
  // ed25519 key is a seed which is used to generate a private key via a clamping procedure
  // we are replacing this with a ristretto255 secret which is a true scalar and returning the canonical ristretto255 public key, which may differ from the ed25519 public key
  // If ed25519SecretKey is 64 bytes (seed + public key), use only the first 32 bytes (seed)
  
  // Step 1: Extract seed (first 32 bytes) if secret key is 64 bytes
  const seed = ed25519SecretKey.length === 64 ? ed25519SecretKey.subarray(0, 32) : ed25519SecretKey
  
  // Step 2: Hash the ed25519 seed using SHA-512 to get 64-byte digest
  const hash = sha512(seed)
  
  // Step 3: Split hash into two 32-byte halves
  const h_L = hash.subarray(0, 32)  // First 32 bytes
  const h_R = hash.subarray(32, 64) // Last 32 bytes
  
  // Step 4: Apply clamping procedure to h_L to get the private scalar
  const clamped = new Uint8Array(h_L)
  clamped[0] &= 248  // Clear the lowest three bits of the first byte
  clamped[31] &= 127 // Clear the highest bit of the last byte
  clamped[31] |= 64  // Set the second highest bit of the last byte
  
  // Step 5: Convert clamped bytes to ristretto255 private scalar
  const privateScalar = ristretto255.Point.Fn.create(bytesToNumberLE(clamped))
  const privateKey = b4a.from(ristretto255.Point.Fn.toBytes(privateScalar))
  
  // Step 6: Generate ristretto255 point and convert to ed25519 public key
  // Normalize to canonical representation (same as upgradePublicKey)
  const ristrettoPoint = ristretto255.Point.BASE.multiply(privateScalar)
  const ed25519Point = normalize(ristrettoPoint)
  const ed25519PublicKey = ed25519Point.toBytes()

  // Step 7: Create key pair structure
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

exports.upgradePublicKey = function (publicKey) {
  const ed25519Point = ed25519.Point.fromBytes(publicKey)
  const ristrettoPoint = new ristretto255.Point(ed25519Point)
  const ed25519Point2 = normalize(ristrettoPoint)
  const upgradedPublicKey = ed25519Point2.toBytes()
  return b4a.from(upgradedPublicKey)
}

exports.keyPair = function (seed) {
  let privateKey

  if (seed) {
    // Use seed to generate deterministic private key
    const scalar = ristretto255_hasher.hashToScalar(seed)
    privateKey = b4a.from(ristretto255.Point.Fn.toBytes(scalar))
  } else {
    // Generate random private key using ristretto255 scalar generation
    const scalar = ristretto255_hasher.hashToScalar(randomBytes(32))
    privateKey = b4a.from(ristretto255.Point.Fn.toBytes(scalar))
  }

  // Derive public key using ristretto255
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
    publicKey: publicKeyBuffer, // edwards curve public key
    secretKey: secretKeyBuffer // ristretto255 private key
  }
}

exports.deriveKeyPair = function (secretKey, bytes) {
  const privateKey = secretKey.subarray(0, 32)
  const privateScalar = ristretto255.Point.Fn.fromBytes(privateKey)
  
  // If no bytes provided, just derive the associated keypair from the scalar
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
  const ristrettoPoint = new ristretto255.Point(ed25519Point)
  const sharedPoint = ristrettoPoint.multiply(privateScalar)
  return b4a.from(sharedPoint.toBytes())
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