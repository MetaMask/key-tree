import { concatBytes } from '@metamask/utils';

import { DeriveChildKeyArgs } from '.';
import { BIP_32_HARDENED_OFFSET } from '../constants';
import { SLIP10Node } from '../SLIP10Node';
import { numberToUint32 } from '../utils';
import {
  DeriveNodeArgs,
  derivePrivateChildKey,
  derivePublicChildKey,
  derivePublicExtension,
  deriveSecretExtension,
  generateEntropy,
  getValidatedPath,
  validateNode,
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
  validateNode(node);

  const { childIndex, isHardened } = getValidatedPath(path, node, curve);

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
}: DeriveNodeArgs): Promise<SLIP10Node> {
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
