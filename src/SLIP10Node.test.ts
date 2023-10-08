import { bytesToHex, hexToBytes } from '@metamask/utils';

import fixtures from '../test/fixtures';
import { BIP44PurposeNodeToken } from './constants';
import { ed25519, secp256k1 } from './curves';
import { compressPublicKey } from './curves/secp256k1';
import { createBip39KeyFromSeed, deriveChildKey } from './derivers/bip39';
import { SLIP10Node } from './SLIP10Node';
import { hexStringToBytes, mnemonicPhraseToBytes } from './utils';

const defaultBip39NodeToken = `bip39:${fixtures.local.mnemonic}` as const;
const defaultBip39BytesToken = mnemonicPhraseToBytes(fixtures.local.mnemonic);

describe('SLIP10Node', () => {
  describe('constructor', () => {
    it('throws an error when the constructor guard is not provided', () => {
      const { privateKey, chainCode } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      expect(
        () =>
          // @ts-expect-error - Constructor is private.
          new SLIP10Node({
            privateKey,
            chainCode,
            depth: 0,
            masterFingerprint: 0,
            parentFingerprint: 0,
            index: 0,
            curve: 'secp256k1',
          }),
      ).toThrow(
        'SLIP10Node can only be constructed using `SLIP10Node.fromJSON`, `SLIP10Node.fromExtendedKey`, or `SLIP10Node.fromDerivationPath`.',
      );
    });
  });

  describe('fromExtendedKey', () => {
    it('initializes a new node from a private key', () => {
      const { privateKey, chainCode } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      const node = SLIP10Node.fromExtendedKey({
        privateKey,
        chainCode,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'secp256k1',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toHaveLength(32);
      expect(node.publicKeyBytes).toHaveLength(65);
    });

    it('initializes a new node from a hexadecimal private key and chain code', () => {
      const { privateKey, chainCode } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      const node = SLIP10Node.fromExtendedKey({
        privateKey,
        chainCode,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'secp256k1',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toHaveLength(32);
      expect(node.publicKeyBytes).toHaveLength(65);
    });

    it('initializes a new ed25519 node from a private key', () => {
      const { privateKey, chainCode } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: ed25519,
      });

      const node = SLIP10Node.fromExtendedKey({
        privateKey,
        chainCode,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'ed25519',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toHaveLength(32);
      expect(node.publicKeyBytes).toHaveLength(33);
    });

    it('initializes a new ed25519 node from a zero private key', () => {
      const node = SLIP10Node.fromExtendedKey({
        privateKey: new Uint8Array(32).fill(0),
        chainCode: new Uint8Array(32).fill(1),
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'ed25519',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toStrictEqual(new Uint8Array(32).fill(0));
      expect(node.publicKeyBytes).toHaveLength(33);
    });

    it('initializes a new node from a public key', () => {
      const { publicKeyBytes, chainCodeBytes } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      const node = SLIP10Node.fromExtendedKey({
        publicKey: publicKeyBytes,
        chainCode: chainCodeBytes,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'secp256k1',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toBeUndefined();
      expect(node.publicKeyBytes).toHaveLength(65);
    });

    it('initializes a new ed25519 node from a public key', () => {
      const { publicKeyBytes, chainCodeBytes } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: ed25519,
      });

      const node = SLIP10Node.fromExtendedKey({
        publicKey: publicKeyBytes,
        chainCode: chainCodeBytes,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'ed25519',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toBeUndefined();
      expect(node.publicKeyBytes).toHaveLength(33);
    });

    it('initializes a new node from a hexadecimal public key and chain code', () => {
      const { publicKey, chainCode } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      const node = SLIP10Node.fromExtendedKey({
        publicKey,
        chainCode,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'secp256k1',
      });

      expect(node.depth).toBe(0);
      expect(node.privateKeyBytes).toBeUndefined();
      expect(node.publicKeyBytes).toHaveLength(65);
    });

    it('initializes a new node from JSON', () => {
      const node = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      expect(SLIP10Node.fromJSON(node.toJSON())).toStrictEqual(node);
    });

    it('initializes a new node from JSON with a public key', () => {
      const { privateKey, chainCode } = deriveChildKey({
        path: fixtures.local.mnemonic,
        curve: secp256k1,
      });

      const node = SLIP10Node.fromExtendedKey({
        privateKey,
        chainCode,
        depth: 0,
        parentFingerprint: 0,
        index: 0,
        curve: 'secp256k1',
      });

      const neuteredNode = node.neuter();

      expect(SLIP10Node.fromJSON(neuteredNode.toJSON())).toStrictEqual(
        neuteredNode,
      );
    });

    it('throws if no public or private key is specified', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          chainCode: new Uint8Array(32).fill(1),
          depth: 0,
          parentFingerprint: 0,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid options: Must provide either a private key or a public key.',
      );
    });

    it('throws if the depth is invalid', () => {
      const inputs = [
        -1,
        0.1,
        -0.1,
        NaN,
        Infinity,
        '0',
        'zero',
        {},
        null,
        undefined,
      ];

      for (const input of inputs) {
        expect(() =>
          SLIP10Node.fromExtendedKey({
            depth: input as any,
            parentFingerprint: 0,
            index: 0,
            publicKey: new Uint8Array(65).fill(1),
            chainCode: new Uint8Array(32).fill(1),
            curve: 'secp256k1',
          }),
        ).toThrow(
          `Invalid HD tree path depth: The depth must be a positive integer. Received: "${String(
            input,
          )}"`,
        );
      }
    });

    it('throws if the parent fingerprint is invalid', () => {
      const inputs = [
        -1,
        0.1,
        -0.1,
        NaN,
        Infinity,
        '0',
        'zero',
        {},
        null,
        undefined,
      ];

      for (const input of inputs) {
        expect(() =>
          SLIP10Node.fromExtendedKey({
            depth: 0,
            parentFingerprint: input as any,
            index: 0,
            publicKey: new Uint8Array(65).fill(1),
            chainCode: new Uint8Array(32).fill(1),
            curve: 'secp256k1',
          }),
        ).toThrow(
          `Invalid parent fingerprint: The fingerprint must be a positive integer. Received: "${String(
            input,
          )}"`,
        );
      }
    });

    it('throws if the private key is invalid', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          privateKey: 'foo',
          chainCode: new Uint8Array(32).fill(1),
          depth: 0,
          parentFingerprint: 0,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow('Value must be a hexadecimal string.');
    });

    it('throws if the private key is not a Uint8Array or hexadecimal string', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          // @ts-expect-error Invalid private key type.
          privateKey: 123,
          chainCode: new Uint8Array(32).fill(1),
          depth: 0,
          parentFingerprint: 0,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid value: Expected an instance of Uint8Array or hexadecimal string.',
      );
    });

    it('throws if the private key is zero for secp256k1', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          privateKey: new Uint8Array(32).fill(0),
          chainCode: new Uint8Array(32).fill(1),
          depth: 0,
          parentFingerprint: 0,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid private key: Value is not a valid secp256k1 private key.',
      );
    });

    it('throws if the depth is zero and the parent fingerprint is not zero', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          privateKey: new Uint8Array(32).fill(1),
          chainCode: new Uint8Array(32).fill(1),
          depth: 0,
          parentFingerprint: 1,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid parent fingerprint: The fingerprint of the root node must be 0. Received: "1".',
      );
    });

    it('throws if the depth is not zero and the parent fingerprint is zero', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          privateKey: new Uint8Array(32).fill(1),
          chainCode: new Uint8Array(32).fill(1),
          depth: 1,
          parentFingerprint: 0,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid parent fingerprint: The fingerprint of a child node must not be 0. Received: "0".',
      );
    });

    it('throws if the depth is >= 2 and the parent fingerprint is equal to the master fingerprint', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          privateKey: new Uint8Array(32).fill(1),
          chainCode: new Uint8Array(32).fill(1),
          depth: 2,
          parentFingerprint: 1,
          masterFingerprint: 1,
          index: 0,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid parent fingerprint: The fingerprint of a child node cannot be equal to the master fingerprint. Received: "1".',
      );
    });

    it('throws if the depth is zero and the index is not zero', () => {
      expect(() =>
        SLIP10Node.fromExtendedKey({
          privateKey: new Uint8Array(32).fill(1),
          chainCode: new Uint8Array(32).fill(1),
          depth: 0,
          parentFingerprint: 0,
          index: 1,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid index: The index of the root node must be 0. Received: "1".',
      );
    });
  });

  describe('fromDerivationPath', () => {
    it('initializes a new node from a derivation path', () => {
      // Ethereum coin type node
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: 'secp256k1',
      });

      expect(node.depth).toBe(2);
      expect(node.toJSON()).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        curve: 'secp256k1',
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });
    });

    it('initializes a new node from a derivation path with a Uint8Array', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39BytesToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: 'secp256k1',
      });

      const stringNode = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: 'secp256k1',
      });

      expect(node.toJSON()).toStrictEqual(stringNode.toJSON());
    });

    it('initializes a new node from a derivation path with a Uint8Array using ed25519', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39BytesToken, `slip10:44'`, `slip10:60'`],
        curve: 'ed25519',
      });

      const stringNode = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, `slip10:44'`, `slip10:60'`],
        curve: 'ed25519',
      });

      expect(node.toJSON()).toStrictEqual(stringNode.toJSON());
    });

    it('throws if the derivation path is empty', () => {
      expect(() =>
        SLIP10Node.fromDerivationPath({
          derivationPath: [] as any,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid derivation path: May not specify an empty derivation path.',
      );
    });

    it('throws if no derivation path is specified', () => {
      expect(() =>
        // @ts-expect-error No derivation path specified
        SLIP10Node.fromDerivationPath({
          curve: 'secp256k1',
        }),
      ).toThrow('Invalid options: Must provide a derivation path.');
    });

    it('throws if the derivation path is of depth 0 and not a single BIP-39 node', () => {
      expect(() =>
        SLIP10Node.fromDerivationPath({
          derivationPath: [`bip32:0'`] as any,
          curve: 'secp256k1',
        }),
      ).toThrow(
        'Invalid HD path segment: The segment must consist of a single BIP-39 node for depths of 0. Received: "bip32:0\'".',
      );
    });

    it('throws an error if attempting to modify the fields of a node', () => {
      const node: any = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: 'secp256k1',
      });

      // getter
      expect(() => (node.privateKey = 'foo')).toThrow(
        /^Cannot set property privateKey of .+ which has only a getter/iu,
      );

      // frozen / readonly
      ['depth', 'privateKeyBytes', 'publicKeyBytes', 'chainCodeBytes'].forEach(
        (property) => {
          expect(() => (node[property] = new Uint8Array(64).fill(1))).toThrow(
            expect.objectContaining({
              name: 'TypeError',
              message: expect.stringMatching(
                `Cannot assign to read only property '${property}' of object`,
              ),
            }),
          );
        },
      );
    });

    it('throws an error if no curve is specified', () => {
      expect(() =>
        // @ts-expect-error No curve specified, but required in type
        SLIP10Node.fromDerivationPath({}),
      ).toThrow('Invalid curve: Must specify a curve.');
    });

    it('throws an error for unsupported curves', () => {
      expect(() =>
        SLIP10Node.fromDerivationPath({
          // @ts-expect-error Invalid curve name for type
          curve: 'foo bar',
          specification: 'bip32',
        }),
      ).toThrow(
        'Invalid curve: Only the following curves are supported: secp256k1, ed25519.',
      );
    });
  });

  describe('derive', () => {
    it('derives a child node', () => {
      const coinTypeNode = `bip32:40'`;
      const targetNode = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          coinTypeNode,
        ],
        curve: 'secp256k1',
      });

      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, BIP44PurposeNodeToken],
        curve: 'secp256k1',
      });

      const childNode = node.derive([coinTypeNode]);

      expect(childNode).toMatchObject({
        depth: targetNode.depth,
        privateKey: targetNode.privateKey,
        chainCode: targetNode.chainCode,
      });
    });

    it('derives a public child node', () => {
      const targetNode = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, 'bip32:0'],
        curve: 'secp256k1',
      });

      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken],
        curve: 'secp256k1',
      }).neuter();

      const childNode = node.derive(['bip32:0']);

      expect(childNode.privateKey).toBeUndefined();
      expect(childNode).toMatchObject({
        depth: targetNode.depth,
        publicKey: targetNode.publicKey,
      });
    });

    it('throws when trying to derive a hardened node without a private key', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, BIP44PurposeNodeToken],
        curve: 'secp256k1',
      });

      expect(() => node.neuter().derive([`bip32:0'`])).toThrow(
        'Invalid parameters: Cannot derive hardened child keys without a private key.',
      );
    });

    it('throws if the child derivation path is zero', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:3'`,
          `bip32:0'`,
        ],
        curve: 'secp256k1',
      });

      expect(() => node.derive([] as any)).toThrow(
        'Invalid HD tree derivation path: Deriving a path of length 0 is not defined',
      );
    });

    it('throws when trying to derive a unhardened node with ed25519', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          `slip10:44'`,
          `slip10:3'`,
          `slip10:0'`,
        ],
        curve: 'ed25519',
      });

      expect(() => node.derive(['slip10:0'])).toThrow(
        'Invalid path: Cannot derive unhardened child keys with ed25519.',
      );
    });
  });

  describe('publicKey', () => {
    const {
      ed25519: { slip10 },
      bip32,
    } = fixtures;

    it.each(slip10)(
      'returns the public key for an ed25519 node',
      ({ hexSeed, keys }) => {
        const { privateKey, chainCode } = createBip39KeyFromSeed(
          hexStringToBytes(hexSeed),
          ed25519,
        );

        for (const { path, publicKey } of keys) {
          const node = SLIP10Node.fromExtendedKey({
            privateKey,
            chainCode,
            curve: 'ed25519',
            depth: 0,
            parentFingerprint: 0,
            index: 0,
          });

          if (path.ours.tuple.length === 0) {
            continue;
          }

          const childNode = node.derive(path.ours.tuple);
          expect(childNode.publicKey).toBe(publicKey);
        }
      },
    );

    it.each(bip32)(
      'returns the public key for an secp256k1 node',
      ({ hexSeed, keys }) => {
        const { privateKey, chainCode } = createBip39KeyFromSeed(
          hexStringToBytes(hexSeed),
          secp256k1,
        );

        for (const { path, publicKey } of keys) {
          const node = SLIP10Node.fromExtendedKey({
            privateKey,
            chainCode,
            curve: 'secp256k1',
            depth: 0,
            parentFingerprint: 0,
            index: 0,
          });

          if (path.ours.tuple.length === 0) {
            continue;
          }

          const childNode = node.derive(path.ours.tuple);
          expect(childNode.publicKey).toBe(publicKey);
        }
      },
    );
  });

  describe('compressedPublicKey', () => {
    it('returns the public key in compressed form', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
        curve: 'secp256k1',
      });

      expect(node.compressedPublicKey).toStrictEqual(
        bytesToHex(compressPublicKey(node.publicKeyBytes)),
      );
    });
  });

  describe('compressedPublicKeyBytes', () => {
    it('returns the public key in compressed form', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
        curve: 'secp256k1',
      });

      expect(node.compressedPublicKeyBytes).toStrictEqual(
        compressPublicKey(node.publicKeyBytes),
      );
    });
  });

  describe('address', () => {
    const { hexSeed, path, sampleAddressIndices } =
      fixtures['ethereumjs-wallet'];

    it.each(sampleAddressIndices)(
      'returns the address for an secp256k1 node',
      ({ index, address }) => {
        const { privateKey, chainCode } = createBip39KeyFromSeed(
          hexToBytes(hexSeed),
          secp256k1,
        );

        const node = SLIP10Node.fromExtendedKey({
          privateKey,
          chainCode,
          curve: 'secp256k1',
          depth: 0,
          parentFingerprint: 0,
          index: 0,
        });

        const childNode = node.derive([...path.ours.tuple, `bip32:${index}`]);

        expect(childNode.address).toBe(address);
      },
    );

    it('throws an error when trying to get an address for an ed25519 node', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken, `slip10:44'`, `slip10:60'`],
        curve: 'ed25519',
      });

      expect(() => node.address).toThrow(
        'Unable to get address for this node: Only secp256k1 is supported.',
      );
    });
  });

  describe('fingerprint', () => {
    it('returns the fingerprint for a public key', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: 'secp256k1',
      });

      expect(node.fingerprint).toBe(3263250961);
    });
  });

  describe('masterFingerprint', () => {
    it('returns the master fingerprint for a node', () => {
      const masterNode = SLIP10Node.fromDerivationPath({
        derivationPath: [defaultBip39NodeToken],
        curve: 'secp256k1',
      });

      const node = masterNode.derive([BIP44PurposeNodeToken, `bip32:60'`]);

      expect(node.masterFingerprint).toBe(3293725253);
      expect(node.masterFingerprint).toBe(masterNode.fingerprint);
    });
  });

  describe('neuter', () => {
    it('returns a SLIP-10 node without a private key', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:0'`,
          `bip32:0'`,
        ],
        curve: 'secp256k1',
      });

      const neuterNode = node.neuter();

      expect(neuterNode.publicKey).toBe(node.publicKey);
      expect(neuterNode.privateKey).toBeUndefined();
      expect(neuterNode.privateKeyBytes).toBeUndefined();
    });
  });

  describe('toJSON', () => {
    it('returns a JSON-compatible representation of the node', () => {
      const node = SLIP10Node.fromDerivationPath({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: 'secp256k1',
      });

      expect(node.depth).toBe(2);

      const nodeJson = node.toJSON();
      expect(nodeJson).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        curve: 'secp256k1',
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });

      expect(JSON.parse(JSON.stringify(nodeJson))).toStrictEqual({
        depth: node.depth,
        masterFingerprint: node.masterFingerprint,
        parentFingerprint: node.parentFingerprint,
        index: node.index,
        curve: 'secp256k1',
        privateKey: node.privateKey,
        publicKey: node.publicKey,
        chainCode: node.chainCode,
      });
    });
  });
});
