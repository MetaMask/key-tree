import { bytesToHex } from '@metamask/utils';

import fixtures from '../test/fixtures';
import { HDPathTuple } from './constants';
import { secp256k1 } from './curves';
import { deriveKeyFromPath, validatePathSegment } from './derivation';
import { derivers } from './derivers';
import { privateKeyToEthAddress } from './derivers/bip32';
import { SLIP10Node } from './SLIP10Node';
import { getUnhardenedBIP32NodeToken, mnemonicPhraseToBytes } from './utils';

const {
  bip32: { deriveChildKey: bip32Derive },
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
    it('derives full BIP-44 paths', async () => {
      // generate keys
      const keys = await Promise.all(
        expectedAddresses.map(async (_, index) => {
          const bip32Part = [
            ...ethereumBip32PathParts,
            getUnhardenedBIP32NodeToken(index),
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

          return deriveKeyFromPath({
            path: multipath,
            curve: 'secp256k1',
            specification: 'bip32',
          });
        }),
      );

      // validate addresses
      keys.forEach(({ privateKeyBytes }, index) => {
        const address = privateKeyToEthAddress(privateKeyBytes as Uint8Array);
        expect(bytesToHex(address)).toStrictEqual(expectedAddresses[index]);
      });
    });

    it('derives from Uint8Array BIP-39 nodes', async () => {
      const keys = await Promise.all(
        expectedAddresses.map(async (_, index) => {
          const bip32Part = [
            ...ethereumBip32PathParts,
            getUnhardenedBIP32NodeToken(index),
          ] as const;

          const multipath = [
            mnemonicPhraseToBytes(mnemonic),
            ...bip32Part,
          ] as HDPathTuple;

          return deriveKeyFromPath({
            path: multipath,
            curve: 'secp256k1',
            specification: 'bip32',
          });
        }),
      );

      // validate addresses
      keys.forEach(({ privateKeyBytes }, index) => {
        const address = privateKeyToEthAddress(privateKeyBytes as Uint8Array);
        expect(bytesToHex(address)).toStrictEqual(expectedAddresses[index]);
      });
    });

    it('derives the correct keys using a previously derived parent key', async () => {
      // generate parent key
      const bip39Part = bip39MnemonicToMultipath(mnemonic);
      const multipath = [bip39Part, ...ethereumBip32PathParts] as HDPathTuple;
      const node = await deriveKeyFromPath({
        path: multipath,
        curve: 'secp256k1',
        specification: 'bip32',
      });

      const keys = await Promise.all(
        expectedAddresses.map(async (_, index) => {
          return deriveKeyFromPath({
            path: [`bip32:${index}`],
            node,
            specification: 'bip32',
          });
        }),
      );

      // validate addresses
      keys.forEach(({ privateKeyBytes }, index) => {
        const address = privateKeyToEthAddress(privateKeyBytes as Uint8Array);
        expect(bytesToHex(address)).toStrictEqual(expectedAddresses[index]);
      });
    });

    it('validates inputs', async () => {
      // generate parent key
      const bip39Part = bip39MnemonicToMultipath(mnemonic);
      const multipath = [bip39Part, ...ethereumBip32PathParts] as const;
      const node = await deriveKeyFromPath({
        path: multipath,
        curve: 'secp256k1',
        specification: 'bip32',
      });

      // Empty segments are forbidden
      await expect(async () =>
        deriveKeyFromPath({ path: [], curve: 'secp256k1' }),
      ).rejects.toThrow(
        /Invalid HD path segment: The segment must not be empty\./u,
      );

      // Malformed multipaths are disallowed
      await expect(async () => {
        const [, ...rest] = multipath;
        return deriveKeyFromPath({
          path: [bip39Part.replace('bip39', 'foo') as any, ...rest],
          curve: 'secp256k1',
        });
      }).rejects.toThrow(
        /Invalid HD path segment: The path segment is malformed\./u,
      );

      await expect(async () => {
        const [, bip32Part1, ...rest] = multipath;
        return deriveKeyFromPath({
          path: [bip39Part, bip32Part1.replace('bip32', 'bar') as any, ...rest],
          curve: 'secp256k1',
        });
      }).rejects.toThrow(
        /Invalid HD path segment: The path segment is malformed\./u,
      );

      await expect(async () => {
        const [, bip32Part1, ...rest] = multipath;
        return deriveKeyFromPath({
          path: [bip39Part, bip32Part1.replace(`44'`, 'xyz') as any, ...rest],
          curve: 'secp256k1',
          specification: 'bip32',
        });
      }).rejects.toThrow(
        /Invalid HD path segment: The path segment is malformed\./u,
      );

      await expect(async () => {
        const [, bip32Part1, ...rest] = multipath;
        return deriveKeyFromPath({
          path: [bip39Part, bip32Part1.replace(`'`, '"') as any, ...rest],
          curve: 'secp256k1',
          specification: 'bip32',
        });
      }).rejects.toThrow(
        /Invalid HD path segment: The path segment is malformed\./u,
      );

      await expect(
        deriveKeyFromPath({
          path: [bip39Part, ethereumBip32PathParts[0]],
          curve: 'secp256k1',
          depth: 0,
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        /Invalid HD path segment: The segment must consist of a single BIP-39 node for depths of 0\. Received:/u,
      );

      // bip39 seed phrase component must be completely lowercase
      await expect(
        deriveKeyFromPath({
          path: [bip39Part.replace('r', 'R') as any],
          curve: 'secp256k1',
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        /Invalid HD path segment: The path segment is malformed\./u,
      );

      // Multipaths that start with bip39 segment require _no_ parentKey
      await expect(
        deriveKeyFromPath({ path: [bip39Part], node, specification: 'bip32' }),
      ).rejects.toThrow(
        /Invalid derivation parameters: May not specify parent key if the path segment starts with a BIP-39 node\./u,
      );

      // Multipaths that start with bip32 segment require parentKey
      await expect(
        deriveKeyFromPath({
          path: [`bip32:1'`],
          curve: 'secp256k1',
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        /Invalid derivation parameters: Must specify parent key if the first node of the path segment is not a BIP-39 node\./u,
      );
    });

    it('throws when no curve or node is specified', async () => {
      await expect(
        deriveKeyFromPath({
          path: [bip39MnemonicToMultipath(mnemonic)],
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        'Invalid arguments: Must specify either a parent node or curve.',
      );
    });

    it('throws when an invalid node is provided', async () => {
      await expect(
        deriveKeyFromPath({
          // @ts-expect-error Invalid node type.
          node: {},
          path: [bip39MnemonicToMultipath(mnemonic)],
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        'Invalid arguments: Node must be a SLIP-10 node or a BIP-44 node when provided.',
      );
    });
  });

  describe('bip32Derive', () => {
    it('derives the expected keys and addresses', async () => {
      // generate parent key
      let node: SLIP10Node;

      /* eslint-disable require-atomic-updates */
      node = await bip39Derive({ path: mnemonic, curve: secp256k1 });
      node = await bip32Derive({
        path: `44'`,
        node,
        curve: secp256k1,
        specification: 'bip32',
      });

      node = await bip32Derive({
        path: `60'`,
        node,
        curve: secp256k1,
        specification: 'bip32',
      });

      node = await bip32Derive({
        path: `0'`,
        node,
        curve: secp256k1,
        specification: 'bip32',
      });

      node = await bip32Derive({
        path: `0`,
        node,
        curve: secp256k1,
        specification: 'bip32',
      });
      /* eslint-enable require-atomic-updates */

      const keys = await Promise.all(
        expectedAddresses.map(async (_, index) => {
          return bip32Derive({
            path: `${index}`,
            node,
            curve: secp256k1,
            specification: 'bip32',
          });
        }),
      );

      // validate addresses
      keys.forEach(({ address }, index) => {
        expect(address).toStrictEqual(expectedAddresses[index]);
      });
    });

    it('throws for invalid inputs', async () => {
      const node = await bip39Derive({ path: mnemonic, curve: secp256k1 });
      const inputs = [
        String(-1),
        String(1.1),
        String(2147483649),
        String(Number.MAX_SAFE_INTEGER),
        String({}),
        String('foo'),
      ];

      for (const input of inputs) {
        // eslint-disable-next-line no-loop-func
        await expect(
          bip32Derive({
            path: input,
            node,
            curve: secp256k1,
            specification: 'bip32',
          }),
        ).rejects.toThrow(
          'Invalid BIP-32 index: The index must be a non-negative decimal integer less than 2147483648.',
        );
      }
    });

    it('throws when no node is specified', async () => {
      await expect(
        bip32Derive({
          path: '0',
          curve: secp256k1,
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        'Invalid parameters: Must specify a node to derive from.',
      );
    });

    it('throws when trying to derive from a public key node', async () => {
      const node = await bip39Derive({ path: mnemonic, curve: secp256k1 });
      const publicNode = node.neuter();

      await expect(
        bip32Derive({
          path: `0'`,
          node: publicNode,
          curve: secp256k1,
          specification: 'bip32',
        }),
      ).rejects.toThrow(
        'Invalid parameters: Cannot derive hardened child keys without a private key.',
      );
    });
  });

  // The outputs of this function are tested in key derivation above
  describe('privateKeyToEthAddress', () => {
    it('throws for invalid inputs', () => {
      [
        new Uint8Array(31).fill(1),
        new Uint8Array(32).fill(0),
        'foo',
        {},
        null,
        undefined,
      ].forEach((invalidInput) => {
        expect(() => privateKeyToEthAddress(invalidInput as any)).toThrow(
          'Invalid key: The key must be a 32-byte, non-zero Uint8Array.',
        );
      });
    });
  });
});

describe('validatePathSegment', () => {
  it('accepts a Uint8Array or string path for the first segment', () => {
    expect(() =>
      validatePathSegment(
        [mnemonicPhraseToBytes(fixtures.local.mnemonic)],
        false,
      ),
    ).not.toThrow();

    expect(() =>
      validatePathSegment([`bip39:${fixtures.local.mnemonic}`], false),
    ).not.toThrow();
  });

  it('does not accept a Uint8Array for BIP-32 segments', () => {
    expect(() =>
      validatePathSegment(
        // @ts-expect-error Invalid type.
        [`bip39:${fixtures.local.mnemonic}`, new Uint8Array(32)],
        false,
      ),
    ).toThrow('Invalid HD path segment: The path segment is malformed.');

    expect(() =>
      validatePathSegment(
        // @ts-expect-error Invalid type.
        [`bip39:${fixtures.local.mnemonic}`, `bip32:0`, new Uint8Array(32)],
        false,
      ),
    ).toThrow('Invalid HD path segment: The path segment is malformed.');
  });
});
