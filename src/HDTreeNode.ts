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
  AnonymizedHDPathTuple,
  ANONYMIZED_ROOT,
  BIP_39,
  UNKNOWN_NODE_TOKEN,
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
  anonymizedPath?: AnonymizedHDPathTuple;
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
   * The path to the node, including the root and the node itself.
   * The derivation schema of any node along the path may or may not be known.
   */
  public readonly path: AnonymizedHDPathTuple;

  /**
   * @param options - Options bag.
   * @param options.depth -
   * @param options.entropy -
   * @param options.derivationPath -
   */
  constructor({
    depth,
    entropy,
    derivationPath,
    anonymizedPath,
  }: HDPathOptions) {
    HDTreeNode._validateConstructorParameters({
      depth,
      entropy,
      derivationPath,
      anonymizedPath,
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

      this.path = HDTreeNode._getAnonymizedPath({
        depth,
        derivationPath,
      });
    } else {
      if (!stringEntropy) {
        throw new Error(
          'Invalid parameters: Must specify entropy if no derivation path is specified.',
        );
      }
      this.entropy = stringEntropy;
      this.path = HDTreeNode._getAnonymizedPath({ depth, anonymizedPath });

      validateHDTreeDepth(depth, null);
    }
    this.depth = depth;

    Object.freeze(this);
  }

  private static _validateConstructorParameters({
    depth,
    entropy,
    derivationPath,
    anonymizedPath,
  }: HDPathOptions) {
    if (derivationPath && anonymizedPath) {
      throw new Error(
        'Invalid parameters: May not specify derivationPath and anonymizedPath',
      );
    }

    if (derivationPath === '') {
      throw new Error(
        'Invalid derivation path: May not specify the empty string.',
      );
    }

    if (anonymizedPath && anonymizedPath.length !== depth) {
      throw new Error(
        'Invalid anonymized path: The anonymized path length must match the specified depth.',
      );
    }

    if (entropy) {
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
      // This performs some validation that we want.
      anonymizedPath: HDTreeNode._getAnonymizedPath({
        depth: newDepth,
        anonymizedPath: [...this.path, ...path] as AnonymizedHDPathTuple,
      }),
    };
    return new HDTreeNode(options);
  }

  private static _getAnonymizedPath({
    depth,
    derivationPath,
    anonymizedPath,
  }: Omit<HDPathOptions, 'entropy'>): AnonymizedHDPathTuple {
    if (!derivationPath && !anonymizedPath) {
      return getUnknownHDPathRepresentation(depth);
    }

    if (derivationPath && anonymizedPath) {
      throw new Error('Invalid _getAnonymizedPath parameters.');
    }

    if (derivationPath) {
      const _derivationPath =
        typeof derivationPath === 'string'
          ? segmentStringToTuple(derivationPath)
          : derivationPath;
      return anonymizeHDPath(_derivationPath);
    }

    if (anonymizedPath) {
      if (anonymizedPath.length - 1 !== depth) {
        throw new Error(
          'Invalid anonymized path: path length does not match the specified depth.',
        );
      }
      validateAnonymizedHDPath(anonymizedPath);
      return anonymizedPath;
    }
    /** istanbul ignore next: unreachable */
    throw new Error('Invalid _getAnonymizedPath parameters.');
  }

  serialize(): Pick<HDTreeNode, 'depth' | 'entropy' | 'path'> {
    return {
      depth: this.depth,
      entropy: this.entropy,
      path: this.path,
    };
  }
}

function anonymizeHDPath(
  path: HDPathTuple | AnonymizedHDPathTuple,
): AnonymizedHDPathTuple {
  const [, ..._path] = path;
  let anonymizedPath: string[];

  if (path[0] === ANONYMIZED_ROOT) {
    anonymizedPath = path;
  } else {
    anonymizedPath = [ANONYMIZED_ROOT];
    _path.forEach((node) => {
      anonymizedPath.push(node);
    });
  }

  validateAnonymizedHDPath(anonymizedPath);
  return anonymizedPath as AnonymizedHDPathTuple;
}

function validateAnonymizedHDPath(path: string[]) {
  if (path.length > MAX_HD_TREE_DEPTH) {
    throw new Error(
      `Anonymized path is too long. The max is 5, found: "${path.length}"`,
    );
  }

  path.forEach((node) => {
    if (node.includes(BIP_39)) {
      throw new Error('Intermediary HD Tree node potentially toxic.');
    }
  });
}

function getUnknownHDPathRepresentation(
  depth: HDTreeDepth,
): AnonymizedHDPathTuple {
  const path = [];
  for (let i = 0; i <= depth; i++) {
    if (i === depth) {
      path.unshift(ANONYMIZED_ROOT);
    } else {
      path.unshift(UNKNOWN_NODE_TOKEN);
    }
  }
  return path as AnonymizedHDPathTuple;
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
