# red25519: ed25519 signatures with ristretto

ed25519 compatible signatures with the flexibility of ristretto-based key derivation

## Installation

```bash
npm install red25519
```

## Usage

see `example.js`

```js
const red25519 = require('red25519')
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

// Detached signing helpers
const signature2 = red25519.signDetached(message, alice.secretKey)
const signature3 = red25519.signKeyPair(alice, message)

// Derive a namespaced keypair
const derivedKeyPair = red25519.deriveKeyPair(alice.secretKey, 'blog') // UTF-8 by default
const derivedKeyPairHex = red25519.deriveKeyPair(alice.secretKey, '626c6f67', 'hex')

// Derive a namespaced public key
const derivedPublicKey = red25519.derivePublicKey(alice.publicKey, 'blog')
console.log(b4a.equals(derivedPublicKey, derivedKeyPair.publicKey)) // true

// Diffie-Hellman
const bob = red25519.keyPair()
const aliceBytes = red25519.deriveSharedSecret(alice.secretKey, bob.publicKey)
const bobBytes = red25519.deriveSharedSecret(bob.secretKey, alice.publicKey)
console.log(b4a.equals(aliceBytes, bobBytes)) // true

// Upgrade an existing ed25519 keypair
const upgradedKeyPair = red25519.upgrade(ed25519SecretKey)
console.log(red25519.validateKeyPair(upgradedKeyPair)) // true

// Upgrade to the canonical ristretto representative of an ed25519 public key
const upgradedPublicKey = red25519.upgradePublicKey(ed25519PublicKey)

// Full key pair upgrade (alias: red25519.upgrade)
const upgradedKeyPair = red25519.upgradeKeyPair(ed25519SecretKey)

console.log(red25519.PUBLIC_KEY_LENGTH) // 32
console.log(red25519.SECRET_KEY_LENGTH) // 64
console.log(red25519.SIGNATURE_LENGTH) // 64
console.log(red25519.SHARED_SECRET_LENGTH) // 32
```

## TypeScript

`red25519` ships a handcrafted `index.d.ts` file that documents the complete API surface, including namespace input overloads and helper functions.
