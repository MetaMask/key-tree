import { assert, bytesToHex, concatBytes, hexToBytes } from '@metamask/utils';

import type { DeriveChildKeyArgs } from '.';
import { generateEntropy, getValidatedPath, validateNode } from './shared';
import { BIP_32_HARDENED_OFFSET } from '../constants';
import type { CryptographicFunctions } from '../cryptography';
import { type Curve, mod } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import { numberToUint32 } from '../utils';

/**
 * CIP-3 https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/CIP-0003.md.
 *
 * CIP-3 defines standards for deriving keys on Cardano.
 *
 * Key attributes.
 * - Root/Master key is derived from entropy, not seed. For this implementation we work with Icarus standard as it is the most widely used.
 * - See https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/Icarus.md.
 *
 * - HD node consists of a 64 byte private key, 32 byte public key and 32 byte chain code.
 * - See https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/CIP-0003.md#master-key-generation.
 *
 * - For derivation of BIP32 HD nodes, it uses modified version called BIP32-Ed25519.
 * - See https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf.
 */

/**
 * Reverses the order of bytes in a Uint8Array.
 *
 * Native BigInt uses big-endian. Since cip3(bip32Edd25519) uses little-endian.
 * We need to reverse the bytes and have separate functions for bigIntToBytes and bytesToBigInt.
 * .slice() is used just to make a copy of the array.
 *
 * @param bytes - The input Uint8Array.
 * @returns A new Uint8Array with the bytes in reversed order.
 */
export const toReversed = (bytes: Uint8Array): Uint8Array =>
  bytes.slice().reverse();

/**
 * Converts an array of bytes to a BigInt.
 *
 * @param bytes - The array of bytes to convert.
 * @returns The BigInt representation of the bytes.
 */
export const bytesToBigInt = (bytes: Uint8Array): bigint => {
  const reversed = toReversed(bytes);
  const bytesInHex = bytesToHex(reversed);
  return BigInt(bytesInHex);
};

/**
 * Converts a BigInt to a byte array.
 *
 * @param bigInt - The BigInt to convert.
 * @returns The byte array representation of the BigInt.
 */
export const bigIntToBytes = (bigInt: bigint): Uint8Array => {
  const hexadecimal = bigInt.toString(16);
  return toReversed(hexToBytes(hexadecimal));
};

/**
 * Pads end of the given bytes array with zeros to a length of 32 bytes.
 *
 * @param bytes - The bytes array to pad.
 * @returns The padded bytes array.
 */
export const padEnd32Bytes = (bytes: Uint8Array): Uint8Array => {
  return concatBytes([
    bytes,
    new Uint8Array(Math.max(32 - bytes.length, 0)).fill(0),
  ]);
};

/**
 * Truncates to first 28 bytes and multiplies by 8.
 *
 * @param bytes - Little-Endian big number in bytes.
 * @returns PadEnd32Bytes(left[0, 28] * 8)).
 */
export const trunc28Mul8 = (bytes: Uint8Array): Uint8Array => {
  const truncLeftMul8 = bytesToBigInt(bytes.slice(0, 28)) * BigInt(8);
  return padEnd32Bytes(bigIntToBytes(truncLeftMul8));
};

/**
 * Does module 2^256.
 *
 * @param bytes - Little-Endian big number in bytes.
 * @returns PadEnd32Bytes(mod(bytes, 2^256))).
 */
export const mod2Pow256 = (bytes: Uint8Array): Uint8Array => {
  return padEnd32Bytes(
    bigIntToBytes(mod(bytesToBigInt(bytes), BigInt(2) ** BigInt(256))),
  );
};

/**
 * Adds the left to the right.
 *
 * @param left - Left hand side Little-Endian big number.
 * @param right - Right hand side Little-Endian big number.
 * @returns PadEnd32Bytes(left + right).
 */
export const add = (left: Uint8Array, right: Uint8Array): Uint8Array => {
  const added = bytesToBigInt(left) + bytesToBigInt(right);
  return padEnd32Bytes(bigIntToBytes(added)).slice(0, 32);
};

/**
 * Concat tag, key and childIndex.
 *
 * @param tag - Key specific tag.
 * @param key - Key.
 * @param childIndex - Child index.
 * @returns PadEnd32Bytes(left + right).
 */
export const getKeyExtension = (
  tag: number,
  key: Uint8Array,
  childIndex: number,
): Uint8Array => {
  return concatBytes([
    new Uint8Array([tag]),
    key,
    numberToUint32(childIndex, true),
  ]);
};

export type Cip3SupportedCurve = Extract<Curve, { name: 'ed25519Bip32' }>;

type DeriveKeyBaseArgs = { childIndex: number };

type DeriveWithPrivateArgs = DeriveKeyBaseArgs & {
  parentNode: {
    privateKeyBytes: Uint8Array;
    chainCodeBytes: Uint8Array;
    publicKeyBytes: Uint8Array;
  };
  isHardened: boolean;
};

const Z_TAGS = {
  normal: 2,
  hardened: 0,
};

/**
 * Derive a private child key.
 *
 * Following "Section V. BIP32-ED25519: SPECIFICATION, C.1,2" in
 * https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf.
 *
 * @param options - The parameters for deriving a child key.
 * @param options.parentNode - The parent node containing private key, chain
 * code, and public key.
 * @param options.childIndex - The index of the child key.
 * @param options.isHardened - Indicates if the child key is hardened.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The derived child key.
 */
export const derivePrivateKey = async (
  { parentNode, childIndex, isHardened }: DeriveWithPrivateArgs,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<Uint8Array> => {
  // extension = i >= 2^31 ? (0x00||kp||i) : (0x02||Ap||i)
  const extension = isHardened
    ? getKeyExtension(
        Z_TAGS.hardened,
        parentNode.privateKeyBytes,
        childIndex + BIP_32_HARDENED_OFFSET,
      )
    : getKeyExtension(Z_TAGS.normal, parentNode.publicKeyBytes, childIndex);

  // entropy = Fcp(extension)
  const entropy = await generateEntropy(
    {
      chainCode: parentNode.chainCodeBytes,
      extension,
    },
    cryptographicFunctions,
  );

  const zl = entropy.subarray(0, 32);
  const zr = entropy.subarray(32);

  const parentKl = parentNode.privateKeyBytes.subarray(0, 32);
  const parentKr = parentNode.privateKeyBytes.subarray(32);

  // 8[ZL] + kPL
  const childKl = add(trunc28Mul8(zl), parentKl);
  // ZR + kPR
  const childKr = add(zr, parentKr);
  return concatBytes([childKl, childKr]);
};

type DeriveWithoutPrivateArgs = DeriveKeyBaseArgs & {
  parentNode: {
    chainCodeBytes: Uint8Array;
    publicKeyBytes: Uint8Array;
  };
  isHardened: false;
};

const CHAIN_CODE_TAGS = {
  normal: 3,
  hardened: 1,
};

/**
 * Derive a child chainCode.
 *
 * Following "Section V. BIP32-ED25519: SPECIFICATION, C.3" in
 * https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf.
 *
 * @param options - The parameters for deriving a child chainCode.
 * @param options.parentNode - The parent node containing optionally a private
 * key, chain code, and public key.
 * @param options.childIndex - The index of the child key.
 * @param options.isHardened - Indicates if the child key is hardened.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The derived child chainCode.
 */
export const deriveChainCode = async (
  {
    parentNode,
    childIndex,
    isHardened,
  }: DeriveWithPrivateArgs | DeriveWithoutPrivateArgs,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<Uint8Array> => {
  // extension = i >= 2^31 ? (0x01||kp||i) : (0x03||Ap||i)
  const extension = isHardened
    ? getKeyExtension(
        CHAIN_CODE_TAGS.hardened,
        parentNode.privateKeyBytes,
        childIndex + BIP_32_HARDENED_OFFSET,
      )
    : getKeyExtension(
        CHAIN_CODE_TAGS.normal,
        parentNode.publicKeyBytes,
        childIndex,
      );

  // entropy = Fcp(extension)
  const entropy = await generateEntropy(
    {
      chainCode: parentNode.chainCodeBytes,
      extension,
    },
    cryptographicFunctions,
  );

  return entropy.subarray(32);
};

const PUBLIC_KEY_TAGS = {
  normal: 2,
};

type DerivePublicKeyArgs = DeriveWithoutPrivateArgs & {
  curve: Cip3SupportedCurve;
};

/**
 * Derive a public key.
 *
 * Following "Section V. BIP32-ED25519: SPECIFICATION, D" in
 * https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf.
 *
 * @param options - The parameters for deriving a child public key.
 * @param options.parentNode - The parent node containing chain code, and public key.
 * @param options.childIndex - The index of the child key.
 * @param options.curve - Derivation curve.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The derived child public key.
 */
export const derivePublicKey = async (
  { parentNode, childIndex, curve }: DerivePublicKeyArgs,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<Uint8Array> => {
  // extension = (0x02||Ap||i)
  const extension = getKeyExtension(
    PUBLIC_KEY_TAGS.normal,
    parentNode.publicKeyBytes,
    childIndex,
  );

  // entropy = Fcp(extension)
  const entropy = await generateEntropy(
    {
      chainCode: parentNode.chainCodeBytes,
      extension,
    },
    cryptographicFunctions,
  );

  const zl = entropy.slice(0, 32);

  // right = [8ZL] * B
  const right = curve.getPublicKey(
    // [8ZL]
    trunc28Mul8(zl),
  );

  // Ai = AP + [8ZL]B,
  return curve.publicAdd(parentNode.publicKeyBytes, right);
};

type Cip3DeriveChildKeyArgs = DeriveChildKeyArgs & {
  curve: Cip3SupportedCurve;
};

/**
 * Derive a SLIP-10 child key with a given path from a parent key.
 *
 * @param options - The options for deriving a child key.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns SLIP10Node.
 */
export async function deriveChildKey(
  options: Cip3DeriveChildKeyArgs,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<SLIP10Node> {
  const { curve, node, path } = options;
  validateNode(node);

  const { childIndex, isHardened } = getValidatedPath(path, node, curve);
  if (curve.name !== 'ed25519Bip32' || !node) {
    throw new Error(
      'Unsupported curve: Only ed25519Bip32 is supported by CIP3.',
    );
  }

  const actualChildIndex =
    childIndex + (isHardened ? BIP_32_HARDENED_OFFSET : 0);

  const {
    privateKeyBytes,
    chainCodeBytes,
    publicKeyBytes,
    masterFingerprint,
    depth,
    fingerprint: parentFingerprint,
  } = node;

  if (privateKeyBytes) {
    const parentNode = {
      privateKeyBytes,
      chainCodeBytes,
      publicKeyBytes,
    };

    const privateKey = await derivePrivateKey(
      {
        parentNode,
        childIndex,
        isHardened,
      },
      cryptographicFunctions,
    );

    const chainCode = await deriveChainCode(
      {
        parentNode,
        childIndex,
        isHardened,
      },
      cryptographicFunctions,
    );

    return SLIP10Node.fromExtendedKey(
      {
        privateKey: bytesToHex(privateKey),
        chainCode: bytesToHex(chainCode),
        masterFingerprint,
        depth: depth + 1,
        parentFingerprint,
        index: actualChildIndex,
        curve: curve.name,
      },
      cryptographicFunctions,
    );
  }

  assert(
    !isHardened,
    'Invalid parameters: Cannot derive hardened child keys without a private key.',
  );

  const parentNode = {
    chainCodeBytes,
    publicKeyBytes,
  };

  const publicKey = await derivePublicKey(
    {
      parentNode,
      childIndex,
      isHardened: false,
      curve,
    },
    cryptographicFunctions,
  );

  const chainCode = await deriveChainCode(
    {
      parentNode,
      childIndex,
      isHardened: false,
    },
    cryptographicFunctions,
  );

  return SLIP10Node.fromExtendedKey(
    {
      publicKey: bytesToHex(publicKey),
      chainCode: bytesToHex(chainCode),
      masterFingerprint,
      depth: depth + 1,
      parentFingerprint,
      index: actualChildIndex,
      curve: curve.name,
    },
    cryptographicFunctions,
  );
}
