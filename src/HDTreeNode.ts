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
  isValidHexStringKey,
  isValidBase64StringKey,
  isValidBufferKey,
} from './utils';

export interface JsonHDTreeNode {
  readonly depth: HDTreeDepth;
  readonly key: string;
}

export type HDTreeNodeInterface = JsonHDTreeNode & {
  toJSON(): JsonHDTreeNode;
};

interface HDPathOptions {
  readonly depth: HDTreeDepth;
  readonly key?: Buffer | string;
  readonly derivationPath?: HDPathTuple;
}

/**
 * - If the depth is 0:
 *   - If there is a path, it must be a single BIP39 node
 * - If the depth is >0:
 *    - If there is a path, the first segment must be a BIP32 node
 *
 * - If there is no key, there must be a path, and the first node
 *   must be a BIP39 node.
 */

/**
 * TODO
 */
export class HDTreeNode implements HDTreeNodeInterface {
  /**
   * The depth of the HD tree node.
   */
  public readonly depth: HDTreeDepth;

  /**
   * The key of the HD tree node, as a Base64 string. Cryptographically, the
   * node itself.
   */
  public readonly key: string;

  /**
   * The key of the HD tree node, as a Node.js Buffer.
   */
  public get keyAsBuffer(): Buffer {
    return base64StringToBuffer(this.key);
  }

  /**
   * @param options - Options bag.
   * @param options.depth -
   * @param options.key -
   * @param options.derivationPath -
   */
  constructor({ depth, key, derivationPath }: HDPathOptions) {
    const [bufferKey, stringKey] = HDTreeNode._parseKey(key);

    if (derivationPath) {
      this.key = deriveStringKeyFromPath(derivationPath, bufferKey, depth);

      validateHDTreeDepth(depth, derivationPath.length);
    } else {
      if (!stringKey) {
        throw new Error(
          'Invalid parameters: Must specify key if no derivation path is specified.',
        );
      }
      this.key = stringKey;
      validateHDTreeDepth(depth, null);
    }
    this.depth = depth;

    Object.freeze(this);
  }

  private static _parseKey(key: unknown) {
    if (key === undefined || key === null) {
      return [undefined, undefined];
    }

    let bufferKey: Buffer;
    let stringKey: string;
    if (typeof key === 'string') {
      if (isValidHexStringKey(key)) {
        bufferKey = hexStringToBuffer(key);
        stringKey = bufferToBase64String(bufferKey);
      } else if (isValidBase64StringKey(key)) {
        stringKey = key;
        bufferKey = base64StringToBuffer(key);
      } else {
        throw new Error(
          'Invalid string key: Must be a 64-byte hexadecimal or Base64 string.',
        );
      }
    } else if (Buffer.isBuffer(key)) {
      if (!isValidBufferKey(key)) {
        throw new Error(
          'Invalid buffer key: Must be a 64-byte, non-empty Buffer.',
        );
      }

      bufferKey = key;
      stringKey = bufferToBase64String(key);
    } else {
      throw new Error(
        `Invalid key: Must be a Buffer or string if specified. Received: "${typeof key}"`,
      );
    }

    return [bufferKey, stringKey] as const;
  }

  public derive(path: PartialHDPathTuple): HDTreeNode {
    if (this.depth === MAX_HD_TREE_DEPTH) {
      throw new Error(
        'Illegal operation: This HD tree path already ends with a leaf node.',
      );
    }

    return deriveChildNode(this.keyAsBuffer, this.depth, path);
  }

  toJSON(): JsonHDTreeNode {
    return {
      depth: this.depth,
      key: this.key,
    };
  }
}

export function deriveChildNode(
  parentKey: Buffer,
  parentDepth: HDTreeDepth,
  pathToChild: PartialHDPathTuple,
) {
  if ((pathToChild as any).length === 0) {
    throw new Error(
      'Invalid HD derivation path: Deriving a path of length 0 is not defined.',
    );
  }

  const newDepth = (parentDepth + pathToChild.length) as HDTreeDepth;
  validateHDTreeDepth(newDepth, null);

  const childKey = deriveKeyFromPath(pathToChild, parentKey);

  return new HDTreeNode({
    depth: newDepth,
    key: childKey,
  });
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
      `Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "${depth}"`,
    );
  }

  if (derivationPathLength !== null && depth !== derivationPathLength - 1) {
    throw new Error(
      `Invalid HD tree path depth: The specified depth does not correspond to the length of the provided HD path: "${derivationPathLength}"`,
    );
  }
}
