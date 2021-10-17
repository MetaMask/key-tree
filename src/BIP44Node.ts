import { deriveKeyFromPath, deriveStringKeyFromPath } from './derivation';
import {
  HDPathTuple,
  MIN_BIP_44_DEPTH,
  MAX_BIP_44_DEPTH,
  BIP44Depth,
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

/**
 * A wrapper for BIP-44 Hierarchical Deterministic (HD) tree nodes, i.e.
 * cryptographic keys used to generate keypairs and addresses for cryptocurrency
 * protocols.
 */
export interface JsonBIP44Node {
  /**
   * The 0-indexed BIP-44 path depth of this node.
   *
   * A BIP-44 path is of the form:
   *
   * `m / purpose' / coin_type' / account' / change / address_index`
   *
   * With the following indices:
   *
   * `0 / 1 / 2 / 3 / 4 / 5`
   */
  readonly depth: BIP44Depth;

  /**
   * The Base64 string representation of the key material for this node.
   */
  readonly key: string;
}

export type BIP44NodeInterface = JsonBIP44Node & {
  /**
   * @returns A JSON-compatible representation of this node's data fields.
   */
  toJSON(): JsonBIP44Node;
};

interface BIP44NodeOptions {
  readonly depth: BIP44Depth;
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
 * `m / purpose' / coin_type' / account' / change / address_index`
 */
export class BIP44Node implements BIP44NodeInterface {
  public readonly depth: BIP44Depth;

  public readonly key: string;

  /**
   * The key of the BIP-44 node, as a Node.js Buffer.
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
  constructor({ depth, key, derivationPath }: BIP44NodeOptions) {
    const [bufferKey, stringKey] = BIP44Node._parseKey(key);

    if (derivationPath) {
      this.key = deriveStringKeyFromPath(derivationPath, bufferKey, depth);

      validateBIP44Depth(depth, derivationPath.length);
    } else {
      if (!stringKey) {
        throw new Error(
          'Invalid parameters: Must specify key if no derivation path is specified.',
        );
      }
      this.key = stringKey;
      validateBIP44Depth(depth, null);
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

  /**
   * `m / purpose' / coin_type' / account' / change / address_index`
   */
  public derive(path: PartialHDPathTuple): BIP44Node {
    if (this.depth === MAX_BIP_44_DEPTH) {
      throw new Error(
        'Illegal operation: This HD tree path already ends with a leaf node.',
      );
    }

    return deriveChildNode(this.keyAsBuffer, this.depth, path);
  }

  toJSON(): JsonBIP44Node {
    return {
      depth: this.depth,
      key: this.key,
    };
  }
}

export function deriveChildNode(
  parentKey: Buffer,
  parentDepth: BIP44Depth,
  pathToChild: PartialHDPathTuple,
) {
  if ((pathToChild as any).length === 0) {
    throw new Error(
      'Invalid HD derivation path: Deriving a path of length 0 is not defined.',
    );
  }

  const newDepth = (parentDepth + pathToChild.length) as BIP44Depth;
  validateBIP44Depth(newDepth, null);

  const childKey = deriveKeyFromPath(pathToChild, parentKey);

  return new BIP44Node({
    depth: newDepth,
    key: childKey,
  });
}

function validateBIP44Depth(
  depth: number,
  derivationPathLength: number | null,
) {
  if (
    !Number.isInteger(depth) ||
    depth < MIN_BIP_44_DEPTH ||
    depth > MAX_BIP_44_DEPTH
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
