import { deriveKeyFromPath, deriveStringKeyFromPath } from './derivation';
import {
  BIP32Node,
  HDPathTuple,
  HDPathString,
  PartialHDPathString,
  PATH_SEPARATOR,
  MIN_HD_TREE_DEPTH,
  MAX_HD_TREE_DEPTH,
  HDTreeDepth,
  KEY_BUFFER_LENGTH,
} from './constants';
import {
  bufferToHexString,
  getHexBuffer,
  isValidHexString,
  stripHexPrefix,
} from './utils';

type AddedHDPathSegmentTuple = BIP32Node[];

function segmentStringToTuple(segment: HDPathString): HDPathTuple {
  return segment.split(PATH_SEPARATOR) as HDPathTuple;
}

function segmentTupleToString(
  segment: HDPathTuple | AddedHDPathSegmentTuple,
): HDPathString | PartialHDPathString {
  return segment.join(PATH_SEPARATOR) as HDPathString | PartialHDPathString;
}

function validateHDTreeDepth(
  depth: number,
  derivationPathLength: number | null,
) {
  if (
    !Number.isInteger(depth) ||
    depth < MIN_HD_TREE_DEPTH ||
    depth > MAX_HD_TREE_DEPTH
  ) {
    throw new Error(
      `Invalid HD Tree Path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "${depth}"`,
    );
  }

  if (derivationPathLength !== null && depth !== derivationPathLength - 1) {
    throw new Error(
      `Invalid HD Tree Path depth: The specified depth does not correspond to the length of the provided HD path: "${derivationPathLength}"`,
    );
  }
}

interface HDPathOptions {
  depth: HDTreeDepth;
  entropy?: Buffer | string;
  derivationPath?: HDPathTuple | HDPathString;
}

/**
 * - If the depth is 0:
 *   - If there is a path, it must be a single BIP39 segment
 * - If the depth is >0:
 *    - If there is a path, the first segment must be a BIP32 segment
 *
 * - If there is no entropy, there must be a path, and the first segment
 *   must be a BIP39 segment.
 */

export class HDTreeNode {
  /**
   * The depth of the HD tree node.
   */
  public readonly depth: HDTreeDepth;

  /**
   * The entropy of the HD tree node. Cryptographically, the node itself.
   */
  public readonly entropy: string;

  /**
   * @param options - Options bag.
   * @param options.depth -
   * @param options.entropy -
   * @param options.derivationPath -
   */
  constructor({ depth, entropy, derivationPath }: HDPathOptions) {
    HDTreeNode._validateConstructorParameters({
      depth,
      entropy,
      derivationPath,
    });

    let stringEntropy, bufferEntropy;
    if (entropy) {
      if (typeof entropy === 'string') {
        stringEntropy = entropy;
        bufferEntropy = getHexBuffer(entropy);
      } else {
        bufferEntropy = entropy;
        stringEntropy = bufferToHexString(entropy);
      }
    }

    if (derivationPath) {
      const stringPath =
        typeof derivationPath === 'string'
          ? derivationPath
          : segmentTupleToString(derivationPath);
      this.entropy = deriveStringKeyFromPath(stringPath, bufferEntropy, depth);

      validateHDTreeDepth(
        depth,
        typeof derivationPath === 'string'
          ? segmentStringToTuple(derivationPath).length
          : derivationPath.length,
      );
    } else {
      if (!stringEntropy) {
        throw new Error(
          'Invalid parameters: Must specify entropy if no derivation path is specified.',
        );
      }
      this.entropy = stringEntropy;
      validateHDTreeDepth(depth, null);
    }
    this.depth = depth;

    Object.freeze(this);
  }

  private static _validateConstructorParameters({
    entropy,
    derivationPath,
  }: Partial<HDPathOptions>) {
    if (derivationPath === '') {
      throw new Error(
        'Invalid derivation path: May not specify the empty string.',
      );
    }

    if (entropy !== undefined && entropy !== null) {
      if (typeof entropy !== 'string' && !Buffer.isBuffer(entropy)) {
        throw new Error(
          `Invalid entropy: Must be a Buffer or string if specified. Received: "${typeof entropy}"`,
        );
      }

      if (Buffer.isBuffer(entropy) && !isValidBufferEntropy(entropy)) {
        throw new Error(
          'Invalid buffer entropy: Must be a 64-byte, non-empty Buffer.',
        );
      }

      if (typeof entropy === 'string' && !isValidStringEntropy(entropy)) {
        throw new Error(
          'Invalid string entropy: Must be a 64-character, nonzero hexadecimal string.',
        );
      }
    }
  }

  public derive(path: AddedHDPathSegmentTuple): HDTreeNode {
    if (this.depth === MAX_HD_TREE_DEPTH) {
      throw new Error(
        'Unable to derive: This HD Tree Path already ends with a leaf node.',
      );
    }

    if (path.length === 0) {
      throw new Error(
        'Invalid HD derivation path: Deriving a path of length 0 is not defined.',
      );
    }

    const newDepth = (this.depth + path.length) as HDTreeDepth;
    validateHDTreeDepth(newDepth, null);

    const newStringPath = segmentTupleToString(path);

    const newEntropy = deriveKeyFromPath(
      newStringPath,
      getHexBuffer(this.entropy),
    );

    const options = {
      depth: newDepth,
      entropy: newEntropy,
    };
    return new HDTreeNode(options);
  }

  toJSON(): Pick<HDTreeNode, 'depth' | 'entropy'> {
    return {
      depth: this.depth,
      entropy: this.entropy,
    };
  }
}

function isValidBufferEntropy(buffer: Buffer): boolean {
  if (buffer.length !== KEY_BUFFER_LENGTH) {
    return false;
  }

  for (const byte of buffer) {
    if (byte !== 0) {
      return true;
    }
  }
  return false;
}

function isValidStringEntropy(stringEntropy: string): boolean {
  if (!isValidHexString(stringEntropy)) {
    return false;
  }

  const stripped = stripHexPrefix(stringEntropy);
  if (stripped.length !== KEY_BUFFER_LENGTH) {
    return false;
  }

  if (/^0+$/iu.test(stripped)) {
    return false;
  }
  return true;
}
