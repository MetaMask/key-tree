import fixtures from '../test/fixtures';
import { HDPathTuple } from './constants';
import { deriveKeyFromPath } from './derivation';
import { derivers } from './derivers';
import { getUnhardenedBIP32Node } from './utils';

const {
  bip32: { deriveChildKey: bip32Derive, privateKeyToEthAddress },
  bip39: { deriveChildKey: bip39Derive, bip39MnemonicToMultipath },
} = derivers;

const { addresses: expectedAddresses, mnemonic } = fixtures.local;
const ethereumBip32PathParts = [
  `bip32:44'`,
  `bip32:60'`,
  `bip32:0'`,
  `bip32:0`,
] as const;

describe('derivation', () => {
  describe('deriveKeyFromPath', () => {
    it('derives full BIP-44 paths', () => {
      // generate keys
      const keys = expectedAddresses.map((_, index) => {
        const bip32Part = [
          ...ethereumBip32PathParts,
          getUnhardenedBIP32Node(index),
        ] as const;
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

    it('derives the correct keys using a previously derived parent key', () => {
      // generate parent key
      const bip39Part = bip39MnemonicToMultipath(mnemonic);
      const multipath = [bip39Part, ...ethereumBip32PathParts] as HDPathTuple;
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

    it('validates inputs', () => {
      // generate parent key
      const bip39Part = bip39MnemonicToMultipath(mnemonic);
      const multipath = [bip39Part, ...ethereumBip32PathParts] as const;
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
  });

  describe('bip32Derive', () => {
    it('derives the expected keys and addresses', () => {
      // generate parent key
      let parentKey: Buffer;
      parentKey = bip39Derive(mnemonic);
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
});
