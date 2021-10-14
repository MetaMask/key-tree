export const KEY_BUFFER_LENGTH = 64 as const;

export const BASE_64_ENTROPY_LENGTH = 88 as const;

export const PATH_SEPARATOR = '/';

export const BIP_39 = 'bip39';

export const MIN_HD_TREE_DEPTH = 0 as const;
export const MAX_HD_TREE_DEPTH = 5 as const;

export type MinHDTreeDepth = typeof MIN_HD_TREE_DEPTH;
export type MaxHDTreeDepth = typeof MAX_HD_TREE_DEPTH;
export type HDTreeDepth = MinHDTreeDepth | 1 | 2 | 3 | 4 | MaxHDTreeDepth;

export type SingleQuoteChar = `'`;

export type BIP39Node = `bip39:${string}`;
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

type RootedHDPathTuple0 = [BIP39Node];
type RootedHDPathTuple1 = [BIP39Node, BIP32Node];
type RootedHDPathTuple2 = [BIP39Node, BIP32Node, BIP32Node];
type RootedHDPathTuple3 = [BIP39Node, BIP32Node, BIP32Node, BIP32Node];

type RootedHDPathTuple4 = [
  BIP39Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
];

type RootedHDPathTuple5 = [
  BIP39Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
];

export type RootedHDPathTuple =
  | RootedHDPathTuple0
  | RootedHDPathTuple1
  | RootedHDPathTuple2
  | RootedHDPathTuple3
  | RootedHDPathTuple4
  | RootedHDPathTuple5;

type PartialHDPathTuple1 = [BIP32Node];
type PartialHDPathTuple2 = [BIP32Node, BIP32Node];
type PartialHDPathTuple3 = [BIP32Node, BIP32Node, BIP32Node];
type PartialHDPathTuple4 = [BIP32Node, BIP32Node, BIP32Node, BIP32Node];
type PartialHDPathTuple5 = [
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
  BIP32Node,
];

export type PartialHDPathTuple =
  | PartialHDPathTuple1
  | PartialHDPathTuple2
  | PartialHDPathTuple3
  | PartialHDPathTuple4
  | PartialHDPathTuple5;

export type HDPathTuple = RootedHDPathTuple | PartialHDPathTuple;

export type FullHDPathTuple = RootedHDPathTuple5;
