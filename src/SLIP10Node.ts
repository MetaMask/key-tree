import {
  BIP_39_PATH_REGEX,
  MIN_BIP_44_DEPTH,
  RootedSLIP10PathTuple,
  SLIP10PathTuple,
} from './constants';
import { Curve } from './curves';
import {
  base64StringToBuffer,
  bufferToBase64String,
  hexStringToBuffer,
  isValidBase64StringKey,
  isValidBufferKey,
  isValidHexStringKey,
} from './utils';
import { deriveKeyFromPath } from './derivation';

/**
 * A wrapper for BIP-44 Hierarchical Deterministic (HD) tree nodes, i.e.
 * cryptographic keys used to generate keypairs and addresses for cryptocurrency
 * protocols.
 */
export type JsonSLIP10Node = {
  /**
   * The 0-indexed path depth of this node.
   */
  readonly depth: number;

  /**
   * The Base64 string representation of the key material for this node.
   */
  readonly key: string;
};

export type SLIP10NodeInterface = JsonSLIP10Node & {
  /**
   * The raw bytes of the key material for this node, as a Node.js Buffer or
   * browser-equivalent.
   */
  keyBuffer: Buffer;

  /**
   * @returns A JSON-compatible representation of this node's data fields.
   */
  toJSON(): JsonSLIP10Node;
};

export type SLIP10NodeOptions = {
  readonly depth?: number;
  readonly key?: Buffer | string;
  readonly derivationPath?: RootedSLIP10PathTuple;
  readonly curve: Curve;
};

type SLIP10NodeConstructorOptions = {
  readonly depth: number;
  readonly key: Buffer;
  readonly curve: Curve;
};

export class SLIP10Node implements SLIP10NodeInterface {
  static async create({
    depth,
    key,
    derivationPath,
    curve,
  }: SLIP10NodeOptions): Promise<SLIP10Node> {
    const _key = SLIP10Node._parseKey(key);

    if (derivationPath) {
      if (_key) {
        throw new Error(
          'Invalid parameters: May not specify a derivation path if a key is specified. Initialize the node with just the parent key and its depth, then call SLIP10Node.derive() with your desired path.',
        );
      }

      if (depth) {
        throw new Error(
          'Invalid parameters: May not specify a depth if a derivation path is specified. The depth will be calculated from the path.',
        );
      }

      if (derivationPath.length === 0) {
        throw new Error(
          'Invalid derivation path: May not specify an empty derivation path.',
        );
      }

      const _depth = derivationPath.length - 1;

      const keyBuffer = await deriveKeyFromPath(
        derivationPath,
        undefined,
        _depth,
      );

      return new SLIP10Node({ depth: _depth, key: keyBuffer, curve });
    } else if (_key) {
      validateBIP32Depth(depth);

      return new SLIP10Node({ depth, key: _key, curve });
    }

    throw new Error(
      'Invalid parameters: Must specify either key or derivation path.',
    );
  }

  /**
   * Constructor helper for validating and parsing the `key` parameter. An error
   * is thrown if validation fails.
   *
   * @param key - The key to parse.
   * @returns A {@link Buffer}, or `undefined` if no key parameter was
   * specified.
   */
  protected static _parseKey(key: unknown): Buffer | undefined {
    if (key === undefined || key === null) {
      return undefined;
    }

    let bufferKey: Buffer;
    if (Buffer.isBuffer(key)) {
      if (!isValidBufferKey(key)) {
        throw new Error(
          'Invalid buffer key: Must be a 64-byte, non-empty Buffer.',
        );
      }

      bufferKey = key;
    } else if (typeof key === 'string') {
      if (isValidHexStringKey(key)) {
        bufferKey = hexStringToBuffer(key);
      } else if (isValidBase64StringKey(key)) {
        bufferKey = base64StringToBuffer(key);
      } else {
        throw new Error(
          'Invalid string key: Must be a 64-byte hexadecimal or Base64 string.',
        );
      }
    } else {
      throw new Error(
        `Invalid key: Must be a Buffer or string if specified. Received: "${typeof key}"`,
      );
    }

    return bufferKey;
  }

  private readonly curve: Curve;

  public readonly depth: number;

  public readonly keyBuffer: Buffer;

  public get key(): string {
    return bufferToBase64String(this.keyBuffer);
  }

  protected constructor({ depth, key, curve }: SLIP10NodeConstructorOptions) {
    this.depth = depth;
    this.keyBuffer = key;
    this.curve = curve;

    // Only freeze if directly instantiated
    if (new.target === SLIP10Node) {
      Object.freeze(this);
    }
  }

  /**
   * Derives a child of the key contains be this node and returns a new
   * {@link SLIP10Node} containing the child key.
   *
   * The specified path must be a valid HD path from this node, per SLIP-10.
   *
   * @param path - The partial (non-rooted) SLIP-10 HD tree path will be used
   * to derive a child key from the parent key contained within this node.
   * @returns The {@link SLIP10Node} corresponding to the derived child key.
   */
  public async derive(path: SLIP10PathTuple): Promise<SLIP10Node> {
    return await deriveChildNode(this.keyBuffer, this.depth, path, this.curve);
  }

  // This is documented in the interface of this class.
  toJSON(): JsonSLIP10Node {
    return {
      depth: this.depth,
      key: this.key,
    };
  }
}

/**
 * Validates a BIP-32 path depth. Effectively, asserts that the depth is an
 * integer `number`. Throws an error if validation fails.
 *
 * @param depth - The depth to validate.
 */
export function validateBIP32Depth(depth: unknown): asserts depth is number {
  if (typeof depth !== 'number' || !Number.isInteger(depth) || depth < 0) {
    throw new Error(
      `Invalid HD tree path depth: The depth must be a positive integer. Received: "${depth}"`,
    );
  }
}

/**
 * Derives a child key from the given parent key, as a {@link BIP44Node}.
 * @param parentKey - The parent key to derive from.
 * @param parentDepth - The depth of the parent key.
 * @param pathToChild - The path to the child node / key.
 * @param curve - The curve to use.
 * @returns The {@link BIP44Node} corresponding to the derived child key.
 */
export async function deriveChildNode(
  parentKey: Buffer,
  parentDepth: number,
  pathToChild: SLIP10PathTuple,
  curve: Curve,
): Promise<SLIP10Node> {
  if (pathToChild.length === 0) {
    throw new Error(
      'Invalid HD tree derivation path: Deriving a path of length 0 is not defined',
    );
  }

  // Note that we do not subtract 1 from the length of the path to the child,
  // unlike when we calculate the depth of a rooted path.
  const newDepth = parentDepth + pathToChild.length;
  validateBIP32Depth(newDepth);
  validateSLIP10DerivationPath(pathToChild, parentDepth + 1);

  return SLIP10Node.create({
    curve,
    depth: newDepth,
    key: await deriveKeyFromPath(pathToChild, parentKey, newDepth, curve),
  });
}

/**
 * Ensures that the given derivation is valid by SLIP-10.
 *
 * @param path - The path to validate.
 * @param startingDepth - The depth of the first node of the derivation path.
 */
function validateSLIP10DerivationPath(
  path: SLIP10PathTuple,
  startingDepth: number,
) {
  if (startingDepth === MIN_BIP_44_DEPTH && !BIP_39_PATH_REGEX.test(path[0])) {
    throw new Error(
      'Invalid derivation path: The "m" / seed node (depth 0) must be a BIP-39 node.',
    );
  }
}