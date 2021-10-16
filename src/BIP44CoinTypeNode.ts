import {
  BIP39Node,
  BIP44PurposeNode,
  CoinTypeHDPathString,
  HardenedBIP32Node,
  HDTreeDepth,
} from './constants';
import {
  JsonHDTreeNode,
  HDTreeNode,
  HDTreeNodeInterface,
  deriveChildNode,
} from './HDTreeNode';
import {
  base64StringToBuffer,
  getBIP44AddressPathTuple,
  getBIP44CoinTypePathString,
  isValidBase64StringKey,
  CoinTypeToAddressIndices,
  getHardenedBIP32Node,
  getUnhardenedBIP32Node,
} from './utils';

export type CoinTypeHDPathTuple = [
  BIP39Node,
  typeof BIP44PurposeNode,
  HardenedBIP32Node,
];
export const COIN_TYPE_DEPTH = 2;

export type JsonBIP44CoinTypeNode = JsonHDTreeNode & {
  readonly coin_type: number;
  readonly path: CoinTypeHDPathString;
};

export type BIP44CoinTypeNodeInterface = HDTreeNodeInterface & {
  readonly coin_type: number;
  readonly path: CoinTypeHDPathString;
};

const InnerNode = Symbol('_node');

export class BIP44CoinTypeNode implements BIP44CoinTypeNodeInterface {
  private readonly [InnerNode]: HDTreeNode;

  public get depth(): HDTreeDepth {
    return this[InnerNode].depth;
  }

  public get key(): string {
    return this[InnerNode].key;
  }

  public readonly path: CoinTypeHDPathString;

  public readonly coin_type: number;

  constructor(
    nodeOrArray: CoinTypeHDPathTuple | HDTreeNode,
    coin_type: number,
  ) {
    this.path = getBIP44CoinTypePathString(coin_type);
    this.coin_type = coin_type;

    if (Array.isArray(nodeOrArray)) {
      this[InnerNode] = new HDTreeNode({
        depth: COIN_TYPE_DEPTH,
        derivationPath: nodeOrArray,
      });
    } else {
      validateCoinTypeNodeDepth(nodeOrArray.depth);
      this[InnerNode] = nodeOrArray;
    }

    Object.freeze(this);
  }

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

function validateCoinTypeParentKey(parentKey: string) {
  if (!isValidBase64StringKey(parentKey)) {
    throw new Error(`Invalid parent key: Must be a 64-byte Base64 string.`);
  }
}

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

export function getBIP44AddressKeyDeriver(
  node: BIP44CoinTypeNode | JsonBIP44CoinTypeNode,
  accountAndChangeIndices?: Omit<CoinTypeToAddressIndices, 'address_index'>,
) {
  const { account = 0, change = 0 } = accountAndChangeIndices || {};
  const { key, depth, coin_type } = node;
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

  bip44AddressKeyDeriver.coin_type = coin_type;
  bip44AddressKeyDeriver.account = account;
  bip44AddressKeyDeriver.change = change;
  Object.freeze(bip44AddressKeyDeriver);
  return bip44AddressKeyDeriver;
}
