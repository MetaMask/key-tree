import { assert, concatBytes } from '@metamask/utils';

import { DeriveChildKeyArgs } from '.';
import { BIP_32_HARDENED_OFFSET } from '../constants';
import { Curve } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import { numberToUint32 } from '../utils';
import {
  derivePrivateChildKey,
  derivePublicChildKey,
  derivePublicExtension,
  deriveSecretExtension,
  generateEntropy,
} from './shared';

/**
 * Derive a SLIP-10 child key with a given path from a parent key.
 *
 * @param options - The options for deriving a child key.
 * @param options.path - The derivation path part to derive.
 * @param options.node - The node to derive from.
 * @param options.curve - The curve to use for derivation.
 * @returns A tuple containing the derived private key, public key and chain
 * code.
 */
export async function deriveChildKey({
  path,
  node,
  curve,
}: DeriveChildKeyArgs): Promise<SLIP10Node> {
  // TODO: Shared validation.
  assert(typeof path === 'string', 'Invalid path: Must be a string.');

  const isHardened = path.includes(`'`);
  if (!isHardened && !curve.deriveUnhardenedKeys) {
    throw new Error(
      `Invalid path: Cannot derive unhardened child keys with ${curve.name}.`,
    );
  }

  if (!node) {
    throw new Error('Invalid parameters: Must specify a node to derive from.');
  }

  if (isHardened && !node.privateKey) {
    throw new Error(
      'Invalid parameters: Cannot derive hardened child keys without a private key.',
    );
  }

  const indexPart = path.split(`'`)[0];
  const childIndex = parseInt(indexPart, 10);

  if (
    !/^\d+$/u.test(indexPart) ||
    !Number.isInteger(childIndex) ||
    childIndex < 0 ||
    childIndex >= BIP_32_HARDENED_OFFSET
  ) {
    throw new Error(
      `Invalid SLIP-10 index: The index must be a non-negative decimal integer less than ${BIP_32_HARDENED_OFFSET}.`,
    );
  }

  const args = {
    chainCode: node.chainCodeBytes,
    childIndex,
    isHardened,
    depth: node.depth,
    parentFingerprint: node.fingerprint,
    masterFingerprint: node.masterFingerprint,
    curve,
  };

  if (node.privateKeyBytes) {
    const secretExtension = await deriveSecretExtension({
      privateKey: node.privateKeyBytes,
      childIndex,
      isHardened,
      curve,
    });

    const entropy = generateEntropy({
      chainCode: node.chainCodeBytes,
      extension: secretExtension,
    });

    return deriveNode({
      privateKey: node.privateKeyBytes,
      entropy,
      ...args,
    });
  }

  const publicExtension = derivePublicExtension({
    parentPublicKey: node.compressedPublicKeyBytes,
    childIndex,
  });

  const entropy = generateEntropy({
    chainCode: node.chainCodeBytes,
    extension: publicExtension,
  });

  return deriveNode({
    publicKey: node.compressedPublicKeyBytes,
    entropy,
    ...args,
  });
}

type BaseDeriveKeyArgs = {
  entropy: Uint8Array;
  chainCode: Uint8Array;
  childIndex: number;
  isHardened: boolean;
  depth: number;
  parentFingerprint: number;
  masterFingerprint?: number;
  curve: Curve;
};

type DerivePrivateKeyArgs = BaseDeriveKeyArgs & {
  privateKey: Uint8Array;
  publicKey?: never;
};

type DerivePublicKeyArgs = BaseDeriveKeyArgs & {
  publicKey: Uint8Array;
  privateKey?: never;
};

type DeriveKeyArgs = DerivePrivateKeyArgs | DerivePublicKeyArgs;

/**
 * Derive a SLIP-10 child key from a parent key.
 *
 * @param options - The options for deriving a child key.
 * @param options.privateKey - The private key to derive from.
 * @param options.publicKey - The public key to derive from.
 * @param options.entropy - The entropy to use for deriving the child key.
 * @param options.chainCode - The chain code to use for deriving the child key.
 * @param options.childIndex - The child index to use for deriving the child key.
 * @param options.isHardened - Whether the child key is hardened.
 * @param options.depth - The depth of the child key.
 * @param options.parentFingerprint - The fingerprint of the parent key.
 * @param options.masterFingerprint - The fingerprint of the master key.
 * @param options.curve - The curve to use for deriving the child key.
 * @returns The derived child key as {@link SLIP10Node}.
 */
async function deriveNode({
  privateKey,
  publicKey,
  entropy,
  chainCode,
  childIndex,
  isHardened,
  depth,
  parentFingerprint,
  masterFingerprint,
  curve,
}: DeriveKeyArgs): Promise<SLIP10Node> {
  try {
    if (privateKey) {
      return await derivePrivateChildKey({
        entropy,
        privateKey,
        depth,
        masterFingerprint,
        parentFingerprint,
        childIndex,
        isHardened,
        curve,
      });
    }

    return await derivePublicChildKey({
      entropy,
      publicKey,
      depth,
      masterFingerprint,
      parentFingerprint,
      childIndex,
      curve,
    });
  } catch (error) {
    if (curve.name === 'ed25519') {
      throw error;
    }

    const actualChildIndex = isHardened
      ? childIndex + BIP_32_HARDENED_OFFSET
      : childIndex;

    // As per SLIP-10, if the resulting key is invalid, the new entropy is
    // generated as follows:
    // Key material (32 bytes), child chain code (32 bytes) =
    //   HMAC-SHA512(parent chain code, 0x01 || chain code from invalid key || index).
    const newEntropy = generateEntropy({
      chainCode,
      extension: concatBytes([
        0x01,
        entropy.slice(32, 64),
        numberToUint32(actualChildIndex),
      ]),
    });

    const args = {
      entropy: newEntropy,
      chainCode,
      childIndex,
      isHardened,
      depth,
      parentFingerprint,
      masterFingerprint,
      curve,
    };

    if (privateKey) {
      return deriveNode({
        ...args,
        privateKey,
      });
    }

    return deriveNode({
      ...args,
      publicKey,
    });
  }
}
