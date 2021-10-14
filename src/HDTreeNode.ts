import { deriveKeyFromPath, deriveStringKeyFromPath } from './derivation';
import {
  HDPathTuple,
  MIN_HD_TREE_DEPTH,
  MAX_HD_TREE_DEPTH,
  HDTreeDepth,
  KEY_BUFFER_LENGTH,
  PartialHDPathTuple,
  BASE_64_ENTROPY_LENGTH,
} from './constants';
import {
  bufferToBase64String,
  base64StringToBuffer,
  hexStringToBuffer,
  isValidHexString,
  stripHexPrefix,
} from './utils';

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
    const [bufferEntropy, stringEntropy] = this._parseEntropy(entropy);

    if (derivationPath) {
      this.entropy = deriveStringKeyFromPath(
        derivationPath,
        bufferEntropy,
        depth,
      );

      validateHDTreeDepth(depth, derivationPath.length);
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

  private _parseEntropy(entropy: unknown) {
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

  public derive(path: PartialHDPathTuple): HDTreeNode {
    if (this.depth === MAX_HD_TREE_DEPTH) {
      throw new Error(
        'Unable to derive: This HD Tree Path already ends with a leaf node.',
      );
    }

    if ((path as any).length === 0) {
      throw new Error(
        'Invalid HD derivation path: Deriving a path of length 0 is not defined.',
      );
    }

    const newDepth = (this.depth + path.length) as HDTreeDepth;
    validateHDTreeDepth(newDepth, null);

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

const BASE_64_ZERO =
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==' as const;

const BASE_64_REGEX =
  /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$/u;

function isValidBase64String(input: string) {
  return BASE_64_REGEX.test(input);
}

function isValidHexStringEntropy(stringEntropy: string): boolean {
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

function isValidBase64StringEntropy(stringEntropy: string): boolean {
  if (!isValidBase64String(stringEntropy)) {
    return false;
  }

  if (stringEntropy.length !== BASE_64_ENTROPY_LENGTH) {
    return false;
  }

  if (stringEntropy === BASE_64_ZERO) {
    return false;
  }
  return true;
}
