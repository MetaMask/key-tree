import {
  BIP39Node,
  BIP44PurposeNode,
  CoinTypeHDPathString,
  HardenedBIP32Node,
  BIP44Depth,
} from './constants';
import {
  JsonBIP44Node,
  BIP44Node,
  BIP44NodeInterface,
  deriveChildNode,
} from './BIP44Node';
import {
  base64StringToBuffer,
  getBIP44AddressPathTuple,
  getBIP44CoinTypePathString,
  isValidBase64StringKey,
  CoinTypeToAddressIndices,
  getHardenedBIP32Node,
  getUnhardenedBIP32Node,
  getBIP44ChangePathString,
} from './utils';

export type CoinTypeHDPathTuple = [
  BIP39Node,
  typeof BIP44PurposeNode,
  HardenedBIP32Node,
];
export const COIN_TYPE_DEPTH = 2;

export type JsonBIP44CoinTypeNode = JsonBIP44Node & {
  readonly coin_type: number;
  readonly path: CoinTypeHDPathString;
};

export type BIP44CoinTypeNodeInterface = BIP44NodeInterface & {
  readonly coin_type: number;
  readonly path: CoinTypeHDPathString;
};

const InnerNode = Symbol('_node');

/**
 * `m / purpose' / coin_type' / account' / change / address_index`
 */
export class BIP44CoinTypeNode implements BIP44CoinTypeNodeInterface {
  private readonly [InnerNode]: BIP44Node;

  public get depth(): BIP44Depth {
    return this[InnerNode].depth;
  }

  public get key(): string {
    return this[InnerNode].key;
  }

  public readonly path: CoinTypeHDPathString;

  public readonly coin_type: number;

  constructor(nodeOrArray: CoinTypeHDPathTuple | BIP44Node, coin_type: number) {
    this.path = getBIP44CoinTypePathString(coin_type);
    this.coin_type = coin_type;

    if (Array.isArray(nodeOrArray)) {
      this[InnerNode] = new BIP44Node({
        depth: COIN_TYPE_DEPTH,
        derivationPath: nodeOrArray,
      });
    } else {
      validateCoinTypeNodeDepth(nodeOrArray.depth);
      this[InnerNode] = nodeOrArray;
    }

    Object.freeze(this);
  }

  /**
   * `m / purpose' / coin_type' / account' / change / address_index`
   */
  deriveBIP44AddressKey({
    account = 0,
    change = 0,
    address_index,
  }: CoinTypeToAddressIndices) {
    return this[InnerNode].derive(
      getBIP44AddressPathTuple({ account, change, address_index }),
    );
  }

  toJSON(): JsonBIP44CoinTypeNode {
    return {
      ...this[InnerNode].toJSON(),
      coin_type: this.coin_type,
      path: this.path,
    };
  }
}

function validateCoinTypeNodeDepth(depth: number) {
  if (depth !== COIN_TYPE_DEPTH) {
    throw new Error(
      `Invalid node: Coin type nodes must be of depth ${COIN_TYPE_DEPTH}. Received: "${depth}"`,
    );
  }
}

/**
 * Validates a `coin_type` Base64 string key. "Parent" is in the name because
 * it's also in the message that's thrown on validation failure.
 *
 * @param parentKey The `coin_type` key to validate.
 */
function validateCoinTypeParentKey(parentKey: string) {
  if (!isValidBase64StringKey(parentKey)) {
    throw new Error(`Invalid parent key: Must be a 64-byte Base64 string.`);
  }
}

/**
 * `m / purpose' / coin_type' / account' / change / address_index`
 *
 * @param parentKeyOrNode - The `coin_type` parent key to derive from.
 * @param indices - The `account`, `change`, and `address_index` used for
 * derivation.
 * @returns The derived `address_index` key for the specified derivation path.
 */
export function deriveBIP44AddressKey(
  parentKeyOrNode: string | BIP44CoinTypeNode | JsonBIP44CoinTypeNode,
  { account = 0, change = 0, address_index }: CoinTypeToAddressIndices,
): string {
  if (typeof parentKeyOrNode !== 'string' && 'depth' in parentKeyOrNode) {
    validateCoinTypeNodeDepth(parentKeyOrNode.depth);
  }

  const parentKey =
    typeof parentKeyOrNode === 'string' ? parentKeyOrNode : parentKeyOrNode.key;
  validateCoinTypeParentKey(parentKey);

  return deriveChildNode(
    base64StringToBuffer(parentKey),
    COIN_TYPE_DEPTH,
    getBIP44AddressPathTuple({ account, change, address_index }),
  ).key;
}

/**
 * `m / purpose' / coin_type' / account' / change / address_index`
 *
 * @param node - The {@link BIP44CoinTypeNode} to derive address keys from.
 * This node contains a BIP-44 key of depth 2, `coin_type`.
 * @param accountAndChangeIndices - The `account` and `change` indices that
 * will be used to derive addresses.
 * @returns The deriver function for the derivation path specified by the
 * `coin_type` node, `account`, and `change` indices.
 */
export function getBIP44AddressKeyDeriver(
  node: BIP44CoinTypeNode | JsonBIP44CoinTypeNode,
  accountAndChangeIndices?: Omit<CoinTypeToAddressIndices, 'address_index'>,
) {
  const { account = 0, change = 0 } = accountAndChangeIndices || {};
  const { key, depth } = node;
  validateCoinTypeNodeDepth(depth);
  validateCoinTypeParentKey(key);

  const accountNode = getHardenedBIP32Node(account);
  const changeNode = getUnhardenedBIP32Node(change);

  const parentKeyBuffer = base64StringToBuffer(key);

  const bip44AddressKeyDeriver = (address_index: number): string => {
    return deriveChildNode(parentKeyBuffer, COIN_TYPE_DEPTH, [
      accountNode,
      changeNode,
      getUnhardenedBIP32Node(address_index),
    ]).key;
  };

  bip44AddressKeyDeriver.path = getBIP44ChangePathString(node.path, {
    account,
    change,
  });
  Object.freeze(bip44AddressKeyDeriver);
  return bip44AddressKeyDeriver;
}
