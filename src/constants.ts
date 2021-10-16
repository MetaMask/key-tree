export const KEY_BUFFER_LENGTH = 64 as const;

export const BASE_64_KEY_LENGTH = 88 as const;

export const BASE_64_ZERO =
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==' as const;

// Source: https://stackoverflow.com/a/475217
export const BASE_64_REGEX =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$/u;

export const MIN_HD_TREE_DEPTH = 0 as const;
export const MAX_HD_TREE_DEPTH = 5 as const;

export type MinHDTreeDepth = typeof MIN_HD_TREE_DEPTH;
export type MaxHDTreeDepth = typeof MAX_HD_TREE_DEPTH;
export type HDTreeDepth = MinHDTreeDepth | 1 | 2 | 3 | 4 | MaxHDTreeDepth;

type SingleQuote = `'`;

// BIP-32 derivation path:
// m / purpose' / coin_type' / account' / change / address_index
//
// Per BIP-43 / BIP-44, "purpose" should always be "44":
// m / 44' / coin_type' / account' / change / address_index
//
// The Ethereum "coin_type" is "60". Here's an example Ethereum HD path for
// "account 0":
// m  / 44' / 60' / 0' / 0 / 0

export type AnonymizedBIP39Node = 'm';
export type BIP39Node = `bip39:${string}`;
export type HardenedBIP32Node = `bip32:${number}${SingleQuote}`;
export type UnhardenedBIP32Node = `bip32:${number}`;
export type BIP32Node = HardenedBIP32Node | UnhardenedBIP32Node;

export const BIP44PurposeNode = `bip32:44'`;

type HDPathString0 = AnonymizedBIP39Node;
type HDPathString1 = `${HDPathString0} / ${HardenedBIP32Node}`;
type HDPathString2 = `${HDPathString1} / ${HardenedBIP32Node}`;
type HDPathString3 = `${HDPathString2} / ${HardenedBIP32Node}`;
type HDPathString4 = `${HDPathString3} / ${UnhardenedBIP32Node}`;
type HDPathString5 = `${HDPathString4} / ${UnhardenedBIP32Node}`;

export type CoinTypeHDPathString = HDPathString2;
export type AddressHDPathString = HDPathString5;

export type HDPathString =
  | HDPathString0
  | HDPathString1
  | HDPathString2
  | HDPathString3
  | HDPathString4
  | HDPathString5;

type RootedHDPathTuple0 = readonly [BIP39Node];
type RootedHDPathTuple1 = readonly [...RootedHDPathTuple0, HardenedBIP32Node];
type RootedHDPathTuple2 = readonly [...RootedHDPathTuple1, HardenedBIP32Node];
type RootedHDPathTuple3 = readonly [...RootedHDPathTuple2, HardenedBIP32Node];
type RootedHDPathTuple4 = readonly [...RootedHDPathTuple3, UnhardenedBIP32Node];
type RootedHDPathTuple5 = readonly [...RootedHDPathTuple4, UnhardenedBIP32Node];

export type RootedHDPathTuple =
  | RootedHDPathTuple0
  | RootedHDPathTuple1
  | RootedHDPathTuple2
  | RootedHDPathTuple3
  | RootedHDPathTuple4
  | RootedHDPathTuple5;

type PartialHDPathTuple1 = readonly [HardenedBIP32Node];
type PartialHDPathTuple2 = readonly [...PartialHDPathTuple1, HardenedBIP32Node];
type PartialHDPathTuple3 = readonly [...PartialHDPathTuple2, HardenedBIP32Node];
type PartialHDPathTuple4 = readonly [
  ...PartialHDPathTuple3,
  UnhardenedBIP32Node,
];
type PartialHDPathTuple5 = readonly [
  ...PartialHDPathTuple4,
  UnhardenedBIP32Node,
];
type PartialHDPathTuple6 = readonly [UnhardenedBIP32Node];
type PartialHDPathTuple7 = readonly [UnhardenedBIP32Node, UnhardenedBIP32Node];
type PartialHDPathTuple8 = readonly [
  HardenedBIP32Node,
  UnhardenedBIP32Node,
  UnhardenedBIP32Node,
];
type PartialHDPathTuple9 = readonly [HardenedBIP32Node, UnhardenedBIP32Node];
type PartialHDPathTuple10 = readonly [
  HardenedBIP32Node,
  HardenedBIP32Node,
  UnhardenedBIP32Node,
];
type PartialHDPathTuple11 = readonly [
  HardenedBIP32Node,
  HardenedBIP32Node,
  UnhardenedBIP32Node,
  UnhardenedBIP32Node,
];

export type CoinTypeToAddressTuple = PartialHDPathTuple8;

export type PartialHDPathTuple =
  | PartialHDPathTuple1
  | PartialHDPathTuple2
  | PartialHDPathTuple3
  | PartialHDPathTuple4
  | PartialHDPathTuple5
  | PartialHDPathTuple6
  | PartialHDPathTuple7
  | PartialHDPathTuple8
  | PartialHDPathTuple9
  | PartialHDPathTuple10
  | PartialHDPathTuple11;

export type HDPathTuple = RootedHDPathTuple | PartialHDPathTuple;

export type FullHDPathTuple = RootedHDPathTuple5;
