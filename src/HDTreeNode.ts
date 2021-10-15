import { deriveKeyFromPath, deriveStringKeyFromPath } from './derivation';
import {
  HDPathTuple,
  MIN_HD_TREE_DEPTH,
  MAX_HD_TREE_DEPTH,
  HDTreeDepth,
  PartialHDPathTuple,
} from './constants';
import {
  bufferToBase64String,
  base64StringToBuffer,
  hexStringToBuffer,
  isValidHexStringEntropy,
  isValidBase64StringEntropy,
  isValidBufferEntropy,
} from './utils';

interface HDPathOptions {
  depth: HDTreeDepth;
  entropy?: Buffer | string;
  derivationPath?: HDPathTuple;
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

/**
 * TODO
 */
export class HDTreeNode {
  /**
   * The depth of the HD tree node.
   */
  public readonly depth: HDTreeDepth;

  /**
   * The entropy of the HD tree node, as a Base64 string. Cryptographically, the
   * node itself.
   */
  public readonly entropy: string;

  /**
   * @param options - Options bag.
   * @param options.depth -
   * @param options.entropy -
   * @param options.derivationPath -
   */
  constructor({ depth, entropy, derivationPath }: HDPathOptions) {
    const [bufferEntropy, stringEntropy] = HDTreeNode._parseEntropy(entropy);

    if (derivationPath) {
      this.entropy = deriveStringKeyFromPath(
        derivationPath,
        bufferEntropy,
        depth,
      );

      HDTreeNode._validateHDTreeDepth(depth, derivationPath.length);
    } else {
      if (!stringEntropy) {
        throw new Error(
          'Invalid parameters: Must specify entropy if no derivation path is specified.',
        );
      }
      this.entropy = stringEntropy;
      HDTreeNode._validateHDTreeDepth(depth, null);
    }
    this.depth = depth;

    Object.freeze(this);
  }

  private static _parseEntropy(entropy: unknown) {
    if (entropy === undefined || entropy === null) {
      return [undefined, undefined];
    }

    let bufferEntropy: Buffer;
    let stringEntropy: string;
    if (typeof entropy === 'string') {
      if (isValidHexStringEntropy(entropy)) {
        bufferEntropy = hexStringToBuffer(entropy);
        stringEntropy = bufferToBase64String(bufferEntropy);
      } else if (isValidBase64StringEntropy(entropy)) {
        stringEntropy = entropy;
        bufferEntropy = base64StringToBuffer(entropy);
      } else {
        throw new Error(
          'Invalid string entropy: Must be a 64-byte hexadecimal or base64 string.',
        );
      }
    } else if (Buffer.isBuffer(entropy)) {
      if (!isValidBufferEntropy(entropy)) {
        throw new Error(
          'Invalid buffer entropy: Must be a 64-byte, non-empty Buffer.',
        );
      }

      bufferEntropy = entropy;
      stringEntropy = bufferToBase64String(entropy);
    } else {
      throw new Error(
        `Invalid entropy: Must be a Buffer or string if specified. Received: "${typeof entropy}"`,
      );
    }

    return [bufferEntropy, stringEntropy] as const;
  }

  private static _validateHDTreeDepth(
    depth: number,
    derivationPathLength: number | null,
  ) {
    if (
      !Number.isInteger(depth) ||
      depth < MIN_HD_TREE_DEPTH ||
      depth > MAX_HD_TREE_DEPTH
    ) {
      throw new Error(
        `Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "${depth}"`,
      );
    }

    if (derivationPathLength !== null && depth !== derivationPathLength - 1) {
      throw new Error(
        `Invalid HD tree path depth: The specified depth does not correspond to the length of the provided HD path: "${derivationPathLength}"`,
      );
    }
  }

  public derive(path: PartialHDPathTuple): HDTreeNode {
    if (this.depth === MAX_HD_TREE_DEPTH) {
      throw new Error(
        'Illegal operation: This HD tree path already ends with a leaf node.',
      );
    }

    if ((path as any).length === 0) {
      throw new Error(
        'Invalid HD derivation path: Deriving a path of length 0 is not defined.',
      );
    }

    const newDepth = (this.depth + path.length) as HDTreeDepth;
    HDTreeNode._validateHDTreeDepth(newDepth, null);

    const newEntropy = deriveKeyFromPath(
      path,
      base64StringToBuffer(this.entropy),
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
