export type ByteArray = Uint8Array;
export type NamespaceInput =
  | string
  | ByteArray
  | ArrayBuffer
  | ArrayBufferView;

export interface NamespaceEncodingOptions {
  encoding?: import('node:buffer').BufferEncoding;
}

export interface KeyPair {
  publicKey: ByteArray;
  secretKey: ByteArray;
}

export function keyPair(seed?: ByteArray): KeyPair;

export function deriveKeyPair(
  secretKey: ByteArray,
  namespace: NamespaceInput,
  encodingOrOptions?: import('node:buffer').BufferEncoding | NamespaceEncodingOptions
): KeyPair;

export function derivePublicKey(
  publicKey: ByteArray,
  namespace: NamespaceInput,
  encodingOrOptions?: import('node:buffer').BufferEncoding | NamespaceEncodingOptions
): ByteArray;

export function deriveSharedSecret(
  secretKey: ByteArray,
  publicKey: ByteArray
): ByteArray;

export function normalizeKeyPair(ed25519SecretKey: ByteArray): KeyPair;
export { normalizeKeyPair as normalize };

export function normalizePublicKey(publicKey: ByteArray): ByteArray;

export function validateKeyPair(keyPair: KeyPair): boolean;

export function sign(message: ByteArray, secretKey: ByteArray): ByteArray;
export function signDetached(message: ByteArray, secretKey: ByteArray): ByteArray;
export function signKeyPair(keyPair: KeyPair, message: ByteArray): ByteArray;

export function verify(
  message: ByteArray,
  signature: ByteArray,
  publicKey: ByteArray
): boolean;

export function randomBytes(size: number): ByteArray;

export const PRIVATE_KEY_LENGTH: number;
export const PUBLIC_KEY_LENGTH: number;
export const SECRET_KEY_LENGTH: number;
export const SIGNATURE_LENGTH: number;
export const SHARED_SECRET_LENGTH: number;
