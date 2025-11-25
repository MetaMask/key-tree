import type { SupportedCurve } from '../curves/curve';

export type CryptographicFunctionsBase = {
  /**
   * Compute the HMAC-SHA-512 of the given data using the given key.
   *
   * @param key - The key to use.
   * @param data - The data to hash.
   * @returns The HMAC-SHA-512 of the data.
   */
  hmacSha512: (key: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;

  /**
   * Compute the PBKDF2 of the given password, salt, iterations, and key length.
   * The hash function used is SHA-512.
   *
   * @param password - The password to hash.
   * @param salt - The salt to use.
   * @param iterations - The number of iterations.
   * @param keyLength - The desired key length in bytes.
   * @returns The PBKDF2 of the password.
   */
  pbkdf2Sha512: (
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    keyLength: number,
  ) => Promise<Uint8Array>;

  /**
   * Compute the SHA-256 of the given data.
   *
   * @param data - The data to hash.
   * @returns The SHA-256 of the data.
   */
  sha256: (data: Uint8Array) => Uint8Array;

  /**
   * Compute the Keccak-256 of the given data.
   *
   * @param data - The data to hash.
   * @returns The Keccak-256 of the data.
   */
  keccak256: (data: Uint8Array) => Uint8Array;

  /**
   * Compute the public key of the given private key using the secp256k1 curve.
   *
   * @param curveName - The name of the curve to use ('ed25519', 'secp256k1', or 'ed25519Bip32').
   * @param privateKey - The private key.
   * @param compressed - Whether the public key should be compressed (only applies to secp256k1).
   * @returns The public key.
   */
  getPublicKeyForCurve: (
    curveName: SupportedCurve,
    privateKey: Uint8Array,
    compressed?: boolean,
  ) => Uint8Array;
};

/**
 * Cryptographic functions that supports the override of the built-in implementations by the user.
 */
export type CryptographicFunctions = Partial<
  Pick<CryptographicFunctionsBase, 'hmacSha512' | 'pbkdf2Sha512'>
>;
