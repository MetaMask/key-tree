import { FullHDPathTuple, HDPathTuple, PartialHDPathTuple } from './constants';
import { deriveKeyFromPath } from './derivation';
import { derivers } from './derivers';

// TODO: Import for further derivation tests
// import crypto from 'crypto';
// import { hdkey } from 'ethereumjs-wallet';
// import { BIP44Node } from './BIP44Node';
// import { getBIP44AddressKeyDeriver } from './BIP44CoinTypeNode';
// import { privateKeyToEthAddress } from './derivers/bip32';
// import { base64StringToBuffer } from './utils';

const {
  bip32: { deriveChildKey: bip32Derive, privateKeyToEthAddress },
  bip39: { deriveChildKey: bip39Derive, bip39MnemonicToMultipath },
} = derivers;

const defaultEthereumPath = ['m', `44'`, `60'`, `0'`, `0`];

/**
 * @param bip32Path
 */
function bip32PathToMultipath(path: string[]): PartialHDPathTuple {
  let pathParts = [...path];
  // strip "m" noop
  if (pathParts[0].toLowerCase() === 'm') {
    pathParts = pathParts.slice(1);
  }
  return pathParts.map(
    (part) => `bip32:${part}`,
  ) as unknown as PartialHDPathTuple;
}

const mnemonic =
  'romance hurry grit huge rifle ordinary loud toss sound congress upset twist';

const expectedAddresses = [
  '5df603999c3d5ca2ab828339a9883585b1bce11b',
  '441c07e32a609afd319ffbb66432b424058bcfe9',
  '1f7c93dfe849c06dd610e77473bfaaef7f183c7c',
  '9e28bae18e0e358b12796697c6546f77d4657527',
  '6e7734c7f4fb973a3800b72fb1a6bf82d85d3d29',
  'f87328a8ea5208946c60dbd9385d4c8533ad5dd8',
  'bdc59c95b5afd6cb0318a24fd390f143fec85d51',
  '05751e88f2d9f0fccffc8d9c5188adaa378d60e4',
  'c4311bfd3fea0238a3f5ced088bd366b33f1e292',
  '7b99c781cbfff075229314ccbdc7f6d9e8440ad9',
];

describe('derivation', () => {
  it('deriveKeyFromPath - full path', () => {
    // generate keys
    const keys = expectedAddresses.map((_, index) => {
      const bip32Part = bip32PathToMultipath([
        ...defaultEthereumPath,
        String(index),
      ]);
      const bip39Part = bip39MnemonicToMultipath(mnemonic);
      const multipath = [bip39Part, ...bip32Part] as HDPathTuple;
      expect(multipath).toStrictEqual([
        `bip39:${mnemonic}`,
        `bip32:44'`,
        `bip32:60'`,
        `bip32:0'`,
        `bip32:0`,
        `bip32:${index}`,
      ]);
      return deriveKeyFromPath(multipath);
    });

    // validate addresses
    keys.forEach((key, index) => {
      const address = privateKeyToEthAddress(key);
      expect(address.toString('hex')).toStrictEqual(expectedAddresses[index]);
    });
  });

  it('deriveKeyFromPath - parent key reuse', () => {
    // generate parent key
    const bip32Part = bip32PathToMultipath(defaultEthereumPath);
    const bip39Part = bip39MnemonicToMultipath(mnemonic);
    const multipath = [bip39Part, ...bip32Part] as HDPathTuple;
    const parentKey = deriveKeyFromPath(multipath);
    const keys = expectedAddresses.map((_, index) => {
      return deriveKeyFromPath([`bip32:${index}`], parentKey);
    });

    // validate addresses
    keys.forEach((key, index) => {
      const address = privateKeyToEthAddress(key);
      expect(address.toString('hex')).toStrictEqual(expectedAddresses[index]);
    });
  });

  it('deriveKeyFromPath - input validation', () => {
    // generate parent key
    const bip32Part = bip32PathToMultipath(defaultEthereumPath);
    const bip39Part = bip39MnemonicToMultipath(mnemonic);
    const multipath = [bip39Part, ...bip32Part] as FullHDPathTuple;
    const parentKey = deriveKeyFromPath(multipath);

    // Malformed multipaths are disallowed
    expect(() => {
      const [, ...rest] = multipath;
      deriveKeyFromPath([bip39Part.replace('bip39', 'foo') as any, ...rest]);
    }).toThrow(/Invalid HD path segment: The path segment is malformed\./u);

    expect(() => {
      const [, bip32Part1, ...rest] = multipath;
      deriveKeyFromPath([
        bip39Part,
        bip32Part1.replace('bip32', 'bar') as any,
        ...rest,
      ]);
    }).toThrow(/Invalid HD path segment: The path segment is malformed\./u);

    expect(() => {
      const [, bip32Part1, ...rest] = multipath;
      deriveKeyFromPath([
        bip39Part,
        bip32Part1.replace(`44'`, 'xyz') as any,
        ...rest,
      ]);
    }).toThrow(/Invalid HD path segment: The path segment is malformed\./u);

    expect(() => {
      const [, bip32Part1, ...rest] = multipath;
      deriveKeyFromPath([
        bip39Part,
        bip32Part1.replace(`'`, '"') as any,
        ...rest,
      ]);
    }).toThrow(/Invalid HD path segment: The path segment is malformed\./u);

    // bip39 seed phrase component must be completely lowercase
    expect(() => {
      deriveKeyFromPath([bip39Part.replace('r', 'R') as any]);
    }).toThrow(/Invalid HD path segment: The path segment is malformed\./u);

    // Multipaths that start with bip39 segment require _no_ parentKey
    expect(() => {
      deriveKeyFromPath([bip39Part], parentKey);
    }).toThrow(
      /Invalid derivation parameters: May not specify parent key if the path segment starts with a BIP-39 node\./u,
    );

    // Multipaths that start with bip32 segment require parentKey
    expect(() => {
      deriveKeyFromPath([`bip32:1'`]);
    }).toThrow(
      /Invalid derivation parameters: Must specify parent key if the first node of the path segment is not a BIP-39 node\./u,
    );

    // parentKey must be a buffer if specified
    expect(() => {
      deriveKeyFromPath([`bip32:1'`], parentKey.toString('base64') as any);
    }).toThrow('Parent key must be a Buffer if specified.');
  });

  it('bip32Derive', () => {
    // generate parent key
    let parentKey: Buffer;
    parentKey = bip39Derive(
      `romance hurry grit huge rifle ordinary loud toss sound congress upset twist`,
    );
    parentKey = bip32Derive(`44'`, parentKey);
    parentKey = bip32Derive(`60'`, parentKey);
    parentKey = bip32Derive(`0'`, parentKey);
    parentKey = bip32Derive(`0`, parentKey);
    const keys = expectedAddresses.map((_, index) => {
      return bip32Derive(`${index}`, parentKey);
    });
    // validate addresses
    keys.forEach((key, index) => {
      const address = privateKeyToEthAddress(key);
      expect(address.toString('hex')).toStrictEqual(expectedAddresses[index]);
    });
  });
});
