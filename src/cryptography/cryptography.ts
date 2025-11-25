import { hmac as nobleHmac } from '@noble/hashes/hmac';
import { pbkdf2Async as noblePbkdf2 } from '@noble/hashes/pbkdf2';
import { ripemd160 as nobleRipemd160 } from '@noble/hashes/ripemd160';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { keccak_256 as nobleKeccak256 } from '@noble/hashes/sha3';
import { sha512 as nobleSha512 } from '@noble/hashes/sha512';

import type {
  CryptographicFunctionsBase,
  CryptographicFunctions,
} from './cryptography.types';
import type { SupportedCurve } from '../curves/curve';
import * as ed25519Curve from '../curves/ed25519';
import * as ed25519Bip32Curve from '../curves/ed25519Bip32';
import * as secp256k1Curve from '../curves/secp256k1';
import { isWebCryptoSupported } from '../utils';

/**
 * Compute the HMAC-SHA-512 of the given data using the given key.
 *
 * This function uses the Web Crypto API if available, falling back to a
 * JavaScript implementation if not.
 *
 * @param key - The key to use.
 * @param data - The data to hash.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The HMAC-SHA-512 of the data.
 */
export async function hmacSha512(
  key: Uint8Array,
  data: Uint8Array,
  cryptographicFunctions: CryptographicFunctions = {},
): Promise<Uint8Array> {
  if (cryptographicFunctions.hmacSha512) {
    return await cryptographicFunctions.hmacSha512(key, data);
  }

  if (isWebCryptoSupported()) {
    const subtleKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-512' },
      false,
      ['sign'],
    );

    const result = await crypto.subtle.sign('HMAC', subtleKey, data);
    return new Uint8Array(result);
  }

  return nobleHmac(nobleSha512, key, data);
}

/**
 * Compute the Keccak-256 of the given data synchronously.
 *
 * Right now this is just a wrapper around `keccak256` from the `@noble/hashes`
 * package, but it's here in case we want to change the implementation in the
 * future to allow for asynchronous hashing.
 *
 * @param data - The data to hash.
 * @returns The Keccak-256 of the data.
 */
export function keccak256(data: Uint8Array): Uint8Array {
  return nobleKeccak256(data);
}

/**
 * Compute the PBKDF2 of the given password, salt, iterations, and key length.
 * The hash function used is SHA-512.
 *
 * @param password - The password to hash.
 * @param salt - The salt to use.
 * @param iterations - The number of iterations.
 * @param keyLength - The desired key length.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The PBKDF2 of the password.
 */
export async function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLength: number,
  cryptographicFunctions: CryptographicFunctions = {},
): Promise<Uint8Array> {
  if (cryptographicFunctions.pbkdf2Sha512) {
    return await cryptographicFunctions.pbkdf2Sha512(
      password,
      salt,
      iterations,
      keyLength,
    );
  }

  if (isWebCryptoSupported()) {
    const key = await crypto.subtle.importKey(
      'raw',
      password,
      { name: 'PBKDF2' },
      false,
      ['deriveBits'],
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: { name: 'SHA-512' },
      },
      key,
      // `keyLength` is the number of bytes, but `deriveBits` expects the
      // number of bits, so we multiply by 8.
      keyLength * 8,
    );

    return new Uint8Array(derivedBits);
  }

  return await noblePbkdf2(nobleSha512, password, salt, {
    c: iterations,
    dkLen: keyLength,
  });
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
 * Right now this is just a wrapper around `sha256` from the `@noble/hashes`
 * package, but it's here in case we want to change the implementation in the
 * future to allow for asynchronous hashing.
 *
 * @param data - The data to hash.
 * @returns The SHA-256 of the data.
 */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/**
 * Get the public key for a given private key using the specified curve.
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
      return ed25519Curve.getPublicKey(privateKey);
    case 'secp256k1':
      return secp256k1Curve.getPublicKey(privateKey, compressed);
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
