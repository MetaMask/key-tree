import fixtures from '../test/fixtures';
import { createBip39KeyFromSeed, deriveChildKey } from './derivers/bip39';
import { hexStringToBuffer } from './utils';
import { compressPublicKey } from './curves/secp256k1';
import {
  encodeExtendedKey,
  PRIVATE_KEY_VERSION,
  PUBLIC_KEY_VERSION,
} from './extended-keys';
import { BIP44Node, BIP44PurposeNodeToken } from '.';

const defaultBip39NodeToken = `bip39:${fixtures.local.mnemonic}` as const;

describe('BIP44Node', () => {
  describe('fromExtendedKey', () => {
    it('initializes a new node from a private key', async () => {
      const { privateKey, chainCode } = await deriveChildKey({
        path: fixtures.local.mnemonic,
      });

      // Ethereum coin type node
      const node = await BIP44Node.fromExtendedKey({
        privateKey,
        chainCode,
        depth: 2,
        parentFingerprint: 0,
        index: 0,
      });

      expect(node.depth).toStrictEqual(2);
      expect(node.toJSON()).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });
    });

    it('initializes a new node from JSON', async () => {
      const { privateKey, chainCode } = await deriveChildKey({
        path: fixtures.local.mnemonic,
      });

      // Ethereum coin type node
      const node = await BIP44Node.fromExtendedKey({
        privateKey,
        chainCode,
        depth: 2,
        parentFingerprint: 0,
        index: 0,
      });

      expect(await BIP44Node.fromJSON(node.toJSON())).toStrictEqual(node);
    });

    it.each(fixtures.bip32)(
      'initializes a node from an extended public key',
      async ({ keys }) => {
        for (const key of keys) {
          const node = await BIP44Node.fromExtendedKey(key.extPubKey);
          expect(node.privateKey).toBeUndefined();
          expect(node.publicKey).toBe(key.publicKey);
        }
      },
    );

    it.each(fixtures.bip32)(
      'initializes a node from an extended private key',
      async ({ keys }) => {
        for (const key of keys) {
          const node = await BIP44Node.fromExtendedKey(key.extPrivKey);
          expect(node.privateKey).toBe(key.privateKey);
          expect(node.publicKey).toBe(key.publicKey);
        }
      },
    );

    it('throws if the depth is invalid', async () => {
      const { privateKey, chainCode } = await deriveChildKey({
        path: fixtures.local.mnemonic,
      });

      await expect(
        BIP44Node.fromExtendedKey({
          depth: 6,
          privateKey,
          chainCode,
          parentFingerprint: 0,
          index: 0,
        }),
      ).rejects.toThrow(
        `Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "6"`,
      );
    });
  });

  describe('fromDerivationPath', () => {
    it('initializes a new node from a derivation path', async () => {
      // Ethereum coin type node
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
      });

      expect(node.depth).toStrictEqual(2);
      expect(node.toJSON()).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });
    });

    it('throws an error if attempting to modify the fields of a node', async () => {
      const node: any = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
      });

      // getter
      ['depth', 'privateKey', 'publicKey', 'address'].forEach((property) => {
        expect(() => (node[property] = Buffer.allocUnsafe(64).fill(1))).toThrow(
          expect.objectContaining({
            name: 'TypeError',
            message: expect.stringMatching(
              /^Cannot set property .+ of .+ which has only a getter/iu,
            ),
          }),
        );
      });
    });

    it('throws if the derivation path is of depth 0 and not a single BIP-39 node', async () => {
      await expect(
        BIP44Node.fromDerivationPath({ derivationPath: [`bip32:0'`] as any }),
      ).rejects.toThrow(
        'Invalid derivation path: The "m" / seed node (depth 0) must be a BIP-39 node.',
      );
    });

    it('throws if the depth 1 node of the derivation path is not the BIP-44 purpose node', async () => {
      await expect(
        BIP44Node.fromDerivationPath({
          derivationPath: [defaultBip39NodeToken, `bip32:43'`] as any,
        }),
      ).rejects.toThrow(
        `Invalid derivation path: The "purpose" node (depth 1) must be the string "${BIP44PurposeNodeToken}".`,
      );
    });

    it('throws if the depth 2 node of the derivation path is not a hardened BIP-32 node', async () => {
      await expect(
        BIP44Node.fromDerivationPath({
          derivationPath: [
            defaultBip39NodeToken,
            BIP44PurposeNodeToken,
            `bip32:60`,
          ] as any,
        }),
      ).rejects.toThrow(
        'Invalid derivation path: The "coin_type" node (depth 2) must be a hardened BIP-32 node.',
      );
    });

    it('throws if the depth 3 node of the derivation path is not a hardened BIP-32 node', async () => {
      await expect(
        BIP44Node.fromDerivationPath({
          derivationPath: [
            defaultBip39NodeToken,
            BIP44PurposeNodeToken,
            `bip32:60'`,
            `bip32:0`,
          ] as any,
        }),
      ).rejects.toThrow(
        'Invalid derivation path: The "account" node (depth 3) must be a hardened BIP-32 node.',
      );
    });

    it('throws if the depth 4 node of the derivation path is not a BIP-32 node', async () => {
      await expect(
        BIP44Node.fromDerivationPath({
          derivationPath: [
            defaultBip39NodeToken,
            BIP44PurposeNodeToken,
            `bip32:60'`,
            `bip32:0'`,
            `bip32:-1`,
          ],
        }),
      ).rejects.toThrow(
        'Invalid derivation path: The "change" node (depth 4) must be a BIP-32 node.',
      );
    });

    it('throws if the depth 5 node of the derivation path is not a BIP-32 node', async () => {
      await expect(
        BIP44Node.fromDerivationPath({
          derivationPath: [
            defaultBip39NodeToken,
            BIP44PurposeNodeToken,
            `bip32:60'`,
            `bip32:0'`,
            `bip32:0`,
            `bip32:-1`,
          ],
        }),
      ).rejects.toThrow(
        'Invalid derivation path: The "address_index" node (depth 5) must be a BIP-32 node.',
      );
    });
  });

  describe('derive', () => {
    it('derives a child node', async () => {
      const coinTypeNode = `bip32:40'`;
      const targetNode = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          coinTypeNode,
        ],
      });

      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, BIP44PurposeNodeToken],
      });

      const childNode = await node.derive([coinTypeNode]);

      expect(childNode).toMatchObject({
        depth: targetNode.depth,
        privateKey: targetNode.privateKey,
        publicKey: targetNode.publicKey,
      });
    });

    it('derives a public child node', async () => {
      const coinTypeNode = `bip32:40'`;
      const targetNode = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          coinTypeNode,
          `bip32:0'`,
          `bip32:0`,
        ],
      });

      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          coinTypeNode,
          `bip32:0'`,
        ],
      });

      const childNode = await node.neuter().derive([`bip32:0`]);

      expect(childNode.privateKey).toBeUndefined();
      expect(childNode.depth).toBe(targetNode.depth);
      expect(childNode.publicKey).toBe(targetNode.publicKey);
    });

    it('throws if the parent node is already a leaf node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:3'`,
          `bip32:0'`,
          `bip32:0`,
          `bip32:0`,
        ],
      });

      await expect(node.derive([`bip32:1`])).rejects.toThrow(
        'Illegal operation: This HD tree node is already a leaf node.',
      );
    });

    it('throws if the child derivation path is zero', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:3'`,
          `bip32:0'`,
        ],
      });

      await expect(node.derive([] as any)).rejects.toThrow(
        'Invalid HD tree derivation path: Deriving a path of length 0 is not defined',
      );
    });

    it('throws if the depth 1 node of the derivation path is not the BIP-44 purpose node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken],
      });

      await expect(node.derive([`bip32:43'`])).rejects.toThrow(
        `Invalid derivation path: The "purpose" node (depth 1) must be the string "${BIP44PurposeNodeToken}".`,
      );
    });

    it('throws if the depth 2 node of the derivation path is not a hardened BIP-32 node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, BIP44PurposeNodeToken],
      });

      await expect(node.derive([`bip32:60`])).rejects.toThrow(
        'Invalid derivation path: The "coin_type" node (depth 2) must be a hardened BIP-32 node.',
      );
    });

    it('throws if the depth 3 node of the derivation path is not a hardened BIP-32 node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
      });

      await expect(node.derive([`bip32:0`])).rejects.toThrow(
        'Invalid derivation path: The "account" node (depth 3) must be a hardened BIP-32 node.',
      );
    });

    it('throws if the depth 4 node of the derivation path is not a BIP-32 node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
          `bip32:0'`,
        ],
      });

      await expect(node.derive([`bip32:-1'`])).rejects.toThrow(
        'Invalid derivation path: The "change" node (depth 4) must be a BIP-32 node.',
      );
    });

    it('throws if the depth 5 node of the derivation path is not a BIP-32 node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
          `bip32:0'`,
          `bip32:0`,
        ],
      });

      await expect(node.derive([`bip32:-1`])).rejects.toThrow(
        'Invalid derivation path: The "address_index" node (depth 5) must be a BIP-32 node.',
      );
    });
  });

  describe('publicKey', () => {
    const { hexSeed, path, sampleAddressIndices } =
      fixtures['ethereumjs-wallet'];

    it.each(sampleAddressIndices)(
      'returns the public key for an secp256k1 node',
      async ({ index, publicKey }) => {
        const { privateKey, chainCode } = await createBip39KeyFromSeed(
          hexStringToBuffer(hexSeed),
        );

        const node = await BIP44Node.fromExtendedKey({
          privateKey,
          chainCode,
          depth: 0,
          parentFingerprint: 0,
          index: 0,
        });

        const childNode = await node.derive([
          ...path.ours.tuple,
          `bip32:${index}`,
        ]);

        expect(childNode.publicKey).toBe(publicKey);
      },
    );
  });

  describe('address', () => {
    const { hexSeed, path, sampleAddressIndices } =
      fixtures['ethereumjs-wallet'];

    it.each(sampleAddressIndices)(
      'returns the address for an secp256k1 node',
      async ({ index, address }) => {
        const { privateKey, chainCode } = await createBip39KeyFromSeed(
          hexStringToBuffer(hexSeed),
        );

        const node = await BIP44Node.fromExtendedKey({
          privateKey,
          chainCode,
          depth: 0,
          parentFingerprint: 0,
          index: 0,
        });

        const childNode = await node.derive([
          ...path.ours.tuple,
          `bip32:${index}`,
        ]);

        expect(childNode.address).toBe(address);
      },
    );
  });

  describe('compressedPublicKeyBuffer', () => {
    it('returns the public key in compressed form', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
      });

      expect(node.compressedPublicKeyBuffer).toStrictEqual(
        compressPublicKey(node.publicKeyBuffer),
      );
    });
  });

  describe('extendedKey', () => {
    it('returns the extended private key for nodes with a private key', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
      });

      const extendedKey = encodeExtendedKey({
        version: PRIVATE_KEY_VERSION,
        privateKey: node.privateKeyBuffer as Buffer,
        chainCode: node.chainCodeBuffer,
        depth: node.depth,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
      });

      expect(node.extendedKey).toStrictEqual(extendedKey);
    });

    it('returns the extended public key for nodes with a public key', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
      });

      const neuteredNode = node.neuter();

      const extendedKey = encodeExtendedKey({
        version: PUBLIC_KEY_VERSION,
        publicKey: neuteredNode.publicKeyBuffer,
        chainCode: neuteredNode.chainCodeBuffer,
        depth: neuteredNode.depth,
        parentFingerprint: neuteredNode.parentFingerprint,
        index: neuteredNode.index,
      });

      expect(neuteredNode.extendedKey).toStrictEqual(extendedKey);
    });
  });

  describe('neuter', () => {
    it('returns a BIP-44 node without a private key', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
      });

      const neuterNode = node.neuter();

      expect(neuterNode.publicKey).toBe(node.publicKey);
      expect(neuterNode.privateKey).toBeUndefined();
      expect(neuterNode.privateKeyBuffer).toBeUndefined();
    });
  });

  describe('toJSON', () => {
    it('returns a JSON-compatible representation of the node', async () => {
      const node = await BIP44Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
      });

      expect(node.depth).toStrictEqual(2);

      const nodeJson = node.toJSON();
      expect(nodeJson).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });

      expect(JSON.parse(JSON.stringify(nodeJson))).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });
    });
  });
});
