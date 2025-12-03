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

## API

All functions are synchronous and return `Uint8Array` instances (Node `Buffer`s) unless otherwise noted.

#### `const keyPair = red25519.keyPair([seed])`

Generate a ristretto private scalar and the matching ed25519 public key. Pass an optional 32-byte seed to derive a deterministic key pair. Returns `{ publicKey, secretKey }`, where `secretKey` packs the private scalar (`secretKey.subarray(0, 32)`) and public key (`secretKey.subarray(32)`).

#### `const derived = red25519.deriveKeyPair(secretKey, namespace[, encodingOrOptions])`

Derive a namespaced key pair from an existing secret key. `namespace` accepts `string`, `Uint8Array`, `ArrayBuffer`, or `TypedArray` inputs. The optional third argument can be a `BufferEncoding` string (for example `'hex'`) or an object `{ encoding }` to control how string namespaces are decoded.

#### `const derivedPublicKey = red25519.derivePublicKey(publicKey, namespace[, encodingOrOptions])`

Deterministically derives the namespaced public key using the same namespace rules as `deriveKeyPair`. `derivedPublicKey` always matches `derived.publicKey`.

#### `const shared = red25519.deriveSharedSecret(secretKey, publicKey)`

Perform a ristretto Diffie-Hellman between a private scalar and a peer’s ed25519 public key. Returns the canonical 32-byte ristretto representative.

#### `const keyPair = red25519.upgradeKeyPair(ed25519SecretKey)`

Converts an ed25519 secret key (32-byte seed or 64-byte seed+public key) into a ristretto-backed key pair with the canonical ed25519 public key. Also exported as `red25519.upgrade`.

#### `const publicKey = red25519.upgradePublicKey(ed25519PublicKey)`

Re-encode an ed25519 public key as its canonical ristretto representative.

#### `const ok = red25519.validateKeyPair(keyPair)`

Checks that `keyPair.publicKey` matches the ristretto scalar stored in `keyPair.secretKey`.

#### `const signature = red25519.sign(message, secretKey)`
#### `const signature = red25519.signDetached(message, secretKey)`
#### `const signature = red25519.signKeyPair(keyPair, message)`

All helpers produce 64-byte ed25519-compatible signatures. `signDetached` is an alias for `sign`, while `signKeyPair` accepts the object returned from `keyPair`, `deriveKeyPair`, or `upgradeKeyPair`.

#### `const ok = red25519.verify(message, signature, publicKey)`

Standard ed25519 verify helper, returning a boolean.

#### `const bytes = red25519.randomBytes(size)`

Wrapper around `@noble/hashes` `randomBytes`.

#### `red25519.PUBLIC_KEY_LENGTH`
#### `red25519.PRIVATE_KEY_LENGTH`
#### `red25519.SECRET_KEY_LENGTH`
#### `red25519.SIGNATURE_LENGTH`
#### `red25519.SHARED_SECRET_LENGTH`

Numeric constants that describe the byte lengths of each primitive, useful for preallocating buffers.

