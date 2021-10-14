export const KEY_BUFFER_LENGTH = 64 as const;

export const PATH_SEPARATOR = '/';

export const BIP_39 = 'bip39';

export const MIN_HD_TREE_DEPTH = 0 as const;
export const MAX_HD_TREE_DEPTH = 5 as const;

export type MinHDTreeDepth = typeof MIN_HD_TREE_DEPTH;
export type MaxHDTreeDepth = typeof MAX_HD_TREE_DEPTH;
export type HDTreeDepth = MinHDTreeDepth | 1 | 2 | 3 | 4 | MaxHDTreeDepth;

export type SingleQuoteChar = `'`;

export type BIP39Node = `bip39:${number}`;
export type BIP32Node = `bip32:${number}${SingleQuoteChar | ''}`;

type HDPathString0 = BIP39Node;
type HDPathString1 = `${BIP39Node}/${BIP32Node}`;
type HDPathString2 = `${BIP39Node}/${BIP32Node}/${BIP32Node}`;

type HDPathString3 = `${BIP39Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}`;

type HDPathString4 =
  `${BIP39Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}`;

type HDPathString5 =
  `${BIP39Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}`;

export type HDPathString =
  | HDPathString0
  | HDPathString1
  | HDPathString2
  | HDPathString3
  | HDPathString4
  | HDPathString5;

type PartialHDPathString1 = `${BIP32Node}`;
type PartialHDPathString2 = `${BIP32Node}/${BIP32Node}`;

type PartialHDPathString3 = `${BIP32Node}/${BIP32Node}/${BIP32Node}`;

type PartialHDPathString4 =
  `${BIP32Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}`;

type PartialHDPathString5 =
  `${BIP32Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}/${BIP32Node}`;

export type PartialHDPathString =
  | PartialHDPathString1
  | PartialHDPathString2
  | PartialHDPathString3
  | PartialHDPathString4
  | PartialHDPathString5;

export const ANONYMIZED_ROOT = 'm' as const;
export const UNKNOWN_NODE_TOKEN = 'bip32:?' as const;

export type AnonymizedRootNode = typeof ANONYMIZED_ROOT;
export type UnknownHDNode = typeof UNKNOWN_NODE_TOKEN;
export type AnonymizedIntermediaryNode = BIP32Node | UnknownHDNode;

type AnonymizedHDPathTuple0 = [AnonymizedRootNode];
type AnonymizedHDPathTuple1 = [AnonymizedRootNode, AnonymizedIntermediaryNode];
type AnonymizedHDPathTuple2 = [
  AnonymizedRootNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
];
type AnonymizedHDPathTuple3 = [
  AnonymizedRootNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
];
type AnonymizedHDPathTuple4 = [
  AnonymizedRootNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
];
type AnonymizedHDPathTuple5 = [
  AnonymizedRootNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
  AnonymizedIntermediaryNode,
];

export type AnonymizedHDPathTuple =
  | AnonymizedHDPathTuple0
  | AnonymizedHDPathTuple1
  | AnonymizedHDPathTuple2
  | AnonymizedHDPathTuple3
  | AnonymizedHDPathTuple4
  | AnonymizedHDPathTuple5;

type HDPathTuple0 = [BIP39Node];
type HDPathTuple1 = [BIP39Node, BIP32Node];
type HDPathTuple2 = [BIP39Node, BIP32Node, BIP32Node];
type HDPathTuple3 = [BIP39Node, BIP32Node, BIP32Node, BIP32Node];

type HDPathTuple4 = [BIP39Node, BIP32Node, BIP32Node, BIP32Node, BIP32Node];

type HDPathTuple5 = [
  BIP39Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
];

export type HDPathTuple =
  | HDPathTuple0
  | HDPathTuple1
  | HDPathTuple2
  | HDPathTuple3
  | HDPathTuple4
  | HDPathTuple5;
