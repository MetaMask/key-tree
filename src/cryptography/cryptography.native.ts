import {
  getPublicKey as nativeGetPublicKeySecp256k1,
  getPublicKeyEd25519 as nativeGetPublicKeyEd25519,
  hmacSha512 as nativeHmacSha512,
  keccak256 as nativeKeccak256,
} from '@metamask/native-utils';
import { ripemd160 as nobleRipemd160 } from '@noble/hashes/ripemd160';
import * as quickCrypto from 'react-native-quick-crypto';

import type { CryptographicFunctionsBase } from './cryptography.types';
import type { SupportedCurve } from '../curves';
import * as ed25519Bip32Curve from '../curves/ed25519Bip32';

/**
 * Compute the HMAC-SHA-512 of the given data using the given key.
 *
 * This function uses the native implementation from @metamask/native-utils.
 *
 * @param key - The key to use.
 * @param data - The data to hash.
 * @returns The HMAC-SHA-512 of the data.
 */
export async function hmacSha512(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  return Promise.resolve(nativeHmacSha512(key, data));
}

/**
 * Compute the Keccak-256 of the given data synchronously.
 *
 * This function uses the native implementation from @metamask/native-utils.
 *
 * @param data - The data to hash.
 * @returns The Keccak-256 of the data.
 */
export function keccak256(data: Uint8Array): Uint8Array {
  return nativeKeccak256(data);
}

/**
 * Compute the PBKDF2 of the given password, salt, iterations, and key length.
 * The hash function used is SHA-512.
 *
 * @param password - The password to hash.
 * @param salt - The salt to use.
 * @param iterations - The number of iterations.
 * @param keyLength - The desired key length.
 * @returns The PBKDF2 of the password.
 */
export async function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLength: number,
): Promise<Uint8Array> {
  const derivedKey = quickCrypto.default.pbkdf2Sync(
    password,
    salt,
    iterations,
    keyLength,
    'sha512',
  );
  return Promise.resolve(new Uint8Array(derivedKey));
}

/**
 * Compute the RIPEMD-160 of the given data.
 *
 * Right now this is just a wrapper around `ripemd160` from the `@noble/hashes`
 * package, but it's here in case we want to change the implementation in the
 * future to allow for asynchronous hashing.
 *
 * @param data - The data to hash.
 * @returns The RIPEMD-160 of the data.
 */
export function ripemd160(data: Uint8Array): Uint8Array {
  return nobleRipemd160(data);
}

/**
 * Compute the SHA-256 of the given data synchronously.
 *
 * This function uses `createHash` from `react-native-quick-crypto`.
 *
 * @param data - The data to hash.
 * @returns The SHA-256 of the data.
 */
export function sha256(data: Uint8Array): Uint8Array {
  const hash = quickCrypto.default.createHash('sha256');
  // Convert Uint8Array to ArrayBuffer for hash.update()
  const arrayBuffer = new Uint8Array(data).buffer;
  hash.update(arrayBuffer);
  return new Uint8Array(hash.digest());
}

/**
 * Get the public key for a given private key using the specified curve.
 *
 * This function uses the native implementations from @metamask/native-utils.
 *
 * @param curveName - The name of the curve to use ('ed25519' or 'secp256k1').
 * @param privateKey - The private key.
 * @param compressed - Whether the public key should be compressed (only applies to secp256k1).
 * @returns The public key.
 */
export function getPublicKeyForCurve(
  curveName: SupportedCurve,
  privateKey: Uint8Array,
  compressed?: boolean,
): Uint8Array {
  switch (curveName) {
    case 'ed25519':
      return nativeGetPublicKeyEd25519(privateKey);
    case 'secp256k1':
      return nativeGetPublicKeySecp256k1(privateKey, compressed);
    case 'ed25519Bip32':
      return ed25519Bip32Curve.getPublicKey(privateKey);
    default:
      // eslint-disable-next-line
      curveName as never;
      throw new Error(`Unsupported curve: ${String(curveName)}`);
  }
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _cryptographicFunctions: CryptographicFunctionsBase = {
  hmacSha512,
  pbkdf2Sha512,
  sha256,
  keccak256,
  getPublicKeyForCurve,
};
