const red25519 = require('./')
const b4a = require('b4a')

// Generate a hybrid ristretto/ed25519 key pair:
const alice = red25519.keyPair()
console.log(alice.publicKey.length) // 32 byte ed25519 key
console.log(alice.secretKey.length) // 32+32 byte ristretto secret key + ed25519 public key

// Create a signature
const message = b4a.from('hello friends')
const signature = red25519.sign(message, alice.secretKey)

// Verifies as a standard ed25519 signature
console.log(red25519.verify(message, signature, alice.publicKey)) // true

// Derive a namespaced keypair
const namespace = b4a.from('blog')
const derivedKeyPair = red25519.deriveKeyPair(alice.secretKey, namespace)

// Derive a namespaced public key
const derivedPublicKey = red25519.derivePublicKey(alice.publicKey, namespace)
console.log(b4a.equals(derivedPublicKey, derivedKeyPair.publicKey)) // true

// Diffie-Hellman
const bob = red25519.keyPair()
const aliceBytes = red25519.deriveSharedSecret(alice.secretKey, bob.publicKey)
const bobBytes = red25519.deriveSharedSecret(bob.secretKey, alice.publicKey)
console.log(b4a.equals(aliceBytes, bobBytes)) // true

// Upgrade an existing ed25519 keypair
const ed25519SecretKey = b4a.from('3cadb716898ad406951d5d31a1a3f66b0697c64a7ddae42685f13e2bb6971da06d54e8f0fc2d9d640619955d306426df90510e6e0ead6311b302963eee9bd5ff', 'hex')
const upgradedKeyPair = red25519.upgrade(ed25519SecretKey)
console.log(red25519.validateKeyPair(upgradedKeyPair)) // true