import {
  assert,
  bytesToBigInt,
  concatBytes,
  hexToBytes,
} from '@metamask/utils';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';

import { DerivedKeys } from '.';
import { BIP_32_HARDENED_OFFSET, UNPREFIXED_PATH_REGEX } from '../constants';
import { Curve, mod } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import { isValidBytesKey, numberToUint32 } from '../utils';

type BaseDeriveNodeArgs = {
  entropy: Uint8Array;
  chainCode: Uint8Array;
  childIndex: number;
  isHardened: boolean;
  depth: number;
  parentFingerprint: number;
  masterFingerprint?: number;
  curve: Curve;
};

type DerivePrivateKeyArgs = BaseDeriveNodeArgs & {
  privateKey: Uint8Array;
  publicKey?: never;
};

type DerivePublicKeyArgs = BaseDeriveNodeArgs & {
  publicKey: Uint8Array;
  privateKey?: never;
};

export type DeriveNodeArgs = DerivePrivateKeyArgs | DerivePublicKeyArgs;

type DeriveSecretExtensionArgs = {
  privateKey: Uint8Array;
  childIndex: number;
  isHardened: boolean;
  curve: Curve;
};

/**
 * Derive a BIP-32 secret extension from a parent key and child index.
 *
 * @param options - The options for deriving a secret extension.
 * @param options.privateKey - The parent private key bytes.
 * @param options.childIndex - The child index to derive.
 * @param options.isHardened - Whether the child index is hardened.
 * @param options.curve - The curve to use for derivation.
 * @returns The secret extension bytes.
 */
export async function deriveSecretExtension({
  privateKey,
  childIndex,
  isHardened,
  curve,
}: DeriveSecretExtensionArgs) {
  if (isHardened) {
    // Hardened child
    return concatBytes([
      new Uint8Array([0]),
      privateKey,
      numberToUint32(childIndex + BIP_32_HARDENED_OFFSET),
    ]);
  }

  // Normal child
  const parentPublicKey = await curve.getPublicKey(privateKey, true);
  return derivePublicExtension({ parentPublicKey, childIndex });
}

type DerivePublicExtensionArgs = {
  parentPublicKey: Uint8Array;
  childIndex: number;
};

/**
 * Derive a BIP-32 public extension from a parent key and child index.
 *
 * @param options - The options for deriving a public extension.
 * @param options.parentPublicKey - The parent public key bytes.
 * @param options.childIndex - The child index to derive.
 * @returns The public extension bytes.
 */
export function derivePublicExtension({
  parentPublicKey,
  childIndex,
}: DerivePublicExtensionArgs) {
  const indexBytes = new Uint8Array(4);
  const view = new DataView(indexBytes.buffer);

  view.setUint32(0, childIndex, false);
  return concatBytes([parentPublicKey, indexBytes]);
}

type GenerateKeyArgs = {
  privateKey: Uint8Array;
  entropy: Uint8Array;
  curve: Curve;
};

/**
 * Derive a BIP-32 key from a parent key and secret extension.
 *
 * @param options - The options for deriving a key.
 * @param options.privateKey - The parent private key bytes.
 * @param options.entropy - The entropy bytes.
 * @param options.curve - The curve to use for derivation.
 * @returns The derived key.
 */
async function generateKey({
  privateKey,
  entropy,
  curve,
}: GenerateKeyArgs): Promise<DerivedKeys & { privateKey: Uint8Array }> {
  const keyMaterial = entropy.slice(0, 32);
  const childChainCode = entropy.slice(32);

  // If curve is ed25519: The returned child key ki is parse256(IL).
  // https://github.com/satoshilabs/slips/blob/133ea52a8e43d338b98be208907e144277e44c0e/slip-0010.md#private-parent-key--private-child-key
  if (curve.name === 'ed25519') {
    const publicKey = await curve.getPublicKey(keyMaterial);
    return { privateKey: keyMaterial, publicKey, chainCode: childChainCode };
  }

  const childPrivateKey = privateAdd(privateKey, keyMaterial, curve);
  const publicKey = await curve.getPublicKey(childPrivateKey);

  return { privateKey: childPrivateKey, publicKey, chainCode: childChainCode };
}

type DerivePrivateChildKeyArgs = {
  entropy: Uint8Array;
  privateKey: Uint8Array;
  depth: number;
  masterFingerprint?: number;
  parentFingerprint: number;
  childIndex: number;
  isHardened: boolean;
  curve: Curve;
};

/**
 * Derive a BIP-32 private child key with a given path from a parent key.
 *
 * @param args - The arguments for deriving a private child key.
 * @param args.entropy - The entropy to use for derivation.
 * @param args.privateKey - The parent private key to use for derivation.
 * @param args.depth - The depth of the parent node.
 * @param args.masterFingerprint - The fingerprint of the master node.
 * @param args.parentFingerprint - The fingerprint of the parent node.
 * @param args.childIndex - The child index to derive.
 * @param args.isHardened - Whether the child index is hardened.
 * @param args.curve - The curve to use for derivation.
 * @returns The derived {@link SLIP10Node}.
 */
export async function derivePrivateChildKey({
  entropy,
  privateKey,
  depth,
  masterFingerprint,
  parentFingerprint,
  childIndex,
  isHardened,
  curve,
}: DerivePrivateChildKeyArgs): Promise<SLIP10Node> {
  const actualChildIndex =
    childIndex + (isHardened ? BIP_32_HARDENED_OFFSET : 0);

  const { privateKey: childPrivateKey, chainCode: childChainCode } =
    await generateKey({
      privateKey,
      entropy,
      curve,
    });

  return await SLIP10Node.fromExtendedKey({
    privateKey: childPrivateKey,
    chainCode: childChainCode,
    depth: depth + 1,
    masterFingerprint,
    parentFingerprint,
    index: actualChildIndex,
    curve: curve.name,
  });
}

type GeneratePublicKeyArgs = {
  publicKey: Uint8Array;
  entropy: Uint8Array;
  curve: Curve;
};

/**
 * Derive a BIP-32 public key from a parent key and public extension.
 *
 * @param options - The options for deriving a public key.
 * @param options.publicKey - The parent public key bytes.
 * @param options.entropy - The entropy bytes.
 * @param options.curve - The curve to use for derivation.
 * @returns The derived public key.
 */
function generatePublicKey({
  publicKey,
  entropy,
  curve,
}: GeneratePublicKeyArgs): DerivedKeys {
  const keyMaterial = entropy.slice(0, 32);
  const childChainCode = entropy.slice(32);

  // This function may fail if the resulting key is invalid.
  const childPublicKey = curve.publicAdd(publicKey, keyMaterial);

  return {
    publicKey: childPublicKey,
    chainCode: childChainCode,
  };
}

type DerivePublicChildKeyArgs = {
  entropy: Uint8Array;
  publicKey: Uint8Array;
  depth: number;
  masterFingerprint?: number;
  parentFingerprint: number;
  childIndex: number;
  curve: Curve;
};

/**
 * Derive a BIP-32 public child key with a given path from a parent key.
 *
 * @param args - The arguments for deriving a public child key.
 * @param args.entropy - The entropy to use for derivation.
 * @param args.publicKey - The parent public key to use for derivation.
 * @param args.depth - The depth of the parent node.
 * @param args.masterFingerprint - The fingerprint of the master node.
 * @param args.parentFingerprint - The fingerprint of the parent node.
 * @param args.childIndex - The child index to derive.
 * @param args.curve - The curve to use for derivation.
 * @returns The derived {@link SLIP10Node}.
 */
export async function derivePublicChildKey({
  entropy,
  publicKey,
  depth,
  masterFingerprint,
  parentFingerprint,
  childIndex,
  curve,
}: DerivePublicChildKeyArgs): Promise<SLIP10Node> {
  const { publicKey: childPublicKey, chainCode: childChainCode } =
    generatePublicKey({
      publicKey,
      entropy,
      curve,
    });

  return await SLIP10Node.fromExtendedKey({
    publicKey: childPublicKey,
    chainCode: childChainCode,
    depth: depth + 1,
    masterFingerprint,
    parentFingerprint,
    index: childIndex,
    curve: curve.name,
  });
}

/**
 * Add a tweak to the private key: `(privateKey + tweak) % n`.
 *
 * @param privateKeyBytes - The private key as 32 byte Uint8Array.
 * @param tweakBytes - The tweak as 32 byte Uint8Array.
 * @param curve - The curve to use.
 * @throws If the private key or tweak is invalid.
 * @returns The private key with the tweak added to it.
 */
export function privateAdd(
  privateKeyBytes: Uint8Array,
  tweakBytes: Uint8Array,
  curve: Curve,
): Uint8Array {
  assert(
    isValidBytesKey(tweakBytes, 32),
    'Invalid tweak: Tweak must be a non-zero 32-byte Uint8Array.',
  );

  const privateKey = bytesToBigInt(privateKeyBytes);
  const tweak = bytesToBigInt(tweakBytes);

  if (tweak >= curve.curve.n) {
    throw new Error('Invalid tweak: Tweak is larger than the curve order.');
  }

  const added = mod(privateKey + tweak, curve.curve.n);
  const bytes = hexToBytes(added.toString(16).padStart(64, '0'));

  if (!curve.isValidPrivateKey(bytes)) {
    throw new Error(
      'Invalid private key or tweak: The resulting private key is invalid.',
    );
  }

  return bytes;
}

type GenerateEntropyArgs = {
  chainCode: Uint8Array;
  extension: Uint8Array;
};

/**
 * Generate 64 bytes of (deterministic) entropy from a chain code and secret
 * extension.
 *
 * @param args - The arguments for generating entropy.
 * @param args.chainCode - The parent chain code bytes.
 * @param args.extension - The extension bytes.
 * @returns The generated entropy bytes.
 */
export function generateEntropy({ chainCode, extension }: GenerateEntropyArgs) {
  return hmac(sha512, chainCode, extension);
}

/**
 * Validate that a node is specified.
 *
 * @param node - The node to validate.
 * @throws If the node is not specified.
 */
export function validateNode(node?: SLIP10Node): asserts node is SLIP10Node {
  assert(node, 'Invalid parameters: Must specify a node to derive from.');
}

/**
 * Validate a path.
 *
 * @param path - The path to validate.
 * @param node - The node to validate the path against.
 * @param curve - The curve to validate the path against.
 * @throws If the path is invalid.
 */
export function validatePath(
  path: string | Uint8Array,
  node: SLIP10Node,
  curve: Curve,
): asserts path is string {
  assert(typeof path === 'string', 'Invalid path: Must be a string.');

  const isHardened = path.endsWith(`'`);
  assert(
    !isHardened || node.privateKey,
    'Invalid parameters: Cannot derive hardened child keys without a private key.',
  );
  assert(
    isHardened || curve.deriveUnhardenedKeys,
    `Invalid path: Cannot derive unhardened child keys with ${curve.name}.`,
  );
}

/**
 * Validate a path and return the child index and whether it is hardened.
 *
 * @param path - The path to validate.
 * @param node - The node to validate the path against.
 * @param curve - The curve to validate the path against.
 * @returns The child index and whether it is hardened.
 */
export function getValidatedPath(
  path: string | Uint8Array,
  node: SLIP10Node,
  curve: Curve,
) {
  validatePath(path, node, curve);

  const indexPart = path.split(`'`)[0];
  const childIndex = parseInt(indexPart, 10);

  if (
    !UNPREFIXED_PATH_REGEX.test(indexPart) ||
    !Number.isInteger(childIndex) ||
    childIndex < 0 ||
    childIndex >= BIP_32_HARDENED_OFFSET
  ) {
    throw new Error(
      `Invalid path: The index must be a non-negative decimal integer less than ${BIP_32_HARDENED_OFFSET}.`,
    );
  }

  return { childIndex, isHardened: path.includes(`'`) };
}
