import fixtures from '../test/fixtures';
import { BIP44Node, BIP44PurposeNode, MIN_BIP_44_DEPTH } from '.';

const defaultBip39Node = `bip39:${fixtures.local.mnemonic}` as const;

describe('BIP44Node', () => {
  describe('constructor', () => {
    it('initializes a new node (depth, derivationPath)', () => {
      // Ethereum coin type node
      const node = new BIP44Node({
        derivationPath: [defaultBip39Node, BIP44PurposeNode, `bip32:60'`],
      });

      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(2);
      expect(node.toJSON()).toStrictEqual({
        depth: 2,
        key: node.key,
      });
    });

    it('initializes a new node (depth, buffer key)', () => {
      const node = new BIP44Node({
        depth: 1,
        key: Buffer.alloc(64).fill(1),
      });

      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(1);
      expect(node.toJSON()).toStrictEqual({
        depth: 1,
        key: node.key,
      });
    });

    it('initializes a new node (depth, Base64 string key)', () => {
      const node = new BIP44Node({
        depth: 3,
        key: Buffer.alloc(64).fill(2).toString('base64'),
      });

      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(3);
      expect(node.toJSON()).toStrictEqual({
        depth: 3,
        key: node.key,
      });
    });

    it('initializes a new node (depth, hex string key)', () => {
      const node = new BIP44Node({
        depth: 3,
        key: Buffer.alloc(64).fill(2).toString('hex'),
      });

      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(3);
      expect(node.toJSON()).toStrictEqual({
        depth: 3,
        key: node.key,
      });
    });

    it('initializes a new node (depth, 0x-prefixed hex string key)', () => {
      const node = new BIP44Node({
        depth: 3,
        key: `0x${Buffer.alloc(64).fill(2).toString('hex')}`,
      });

      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(3);
      expect(node.toJSON()).toStrictEqual({
        depth: 3,
        key: node.key,
      });
    });

    it('throws an error if attempting to modify the fields of a node', () => {
      const node: any = new BIP44Node({
        derivationPath: [defaultBip39Node, BIP44PurposeNode, `bip32:60'`],
      });

      // getter
      expect(() => (node.key = 'foo')).toThrow(
        /^Cannot set property key of .+ which has only a getter/iu,
      );

      // frozen / readonly
      ['depth', 'keyBuffer'].forEach((property) => {
        expect(() => (node[property] = Buffer.allocUnsafe(64).fill(1))).toThrow(
          expect.objectContaining({
            name: 'TypeError',
            message: expect.stringMatching(
              `Cannot assign to read only property '${property}' of object`,
            ),
          }),
        );
      });
    });

    it('throws if the depth is invalid', () => {
      const validBufferKey = Buffer.alloc(64).fill(1);

      [
        -1,
        6,
        0.1,
        -0.1,
        NaN,
        Infinity,
        '0',
        'zero',
        {},
        null,
        undefined,
      ].forEach((invalidDepth) => {
        expect(
          () =>
            new BIP44Node({ depth: invalidDepth as any, key: validBufferKey }),
        ).toThrow(
          `Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "${invalidDepth}"`,
        );
      });
    });

    it('throws if both a derivation path and a depth are specified', () => {
      expect(
        () =>
          new BIP44Node({
            depth: 2, // This is the correct depth, but it's still forbidden
            derivationPath: [defaultBip39Node, BIP44PurposeNode, `bip32:60'`],
          }),
      ).toThrow(
        'Invalid parameters: May not specify a depth if a derivation path is specified. The depth will be calculated from the path.',
      );
    });

    it('throws if neither a derivation path nor a key is specified', () => {
      expect(() => new BIP44Node({ depth: 1 })).toThrow(
        'Invalid parameters: Must specify either key or derivation path.',
      );
    });

    it('throws if both a derivation path and a key are specified', () => {
      expect(
        () =>
          new BIP44Node({
            depth: 1,
            derivationPath: [defaultBip39Node],
            key: Buffer.alloc(64).fill(1),
          }),
      ).toThrow(
        'Invalid parameters: May not specify a derivation path if a key is specified. Initialize the node with just the parent key and its depth, then call BIP44Node.derive() with your desired path.',
      );
    });

    it('throws if the derivation path is empty', () => {
      expect(() => new BIP44Node({ derivationPath: [] as any })).toThrow(
        'Invalid derivation path: May not specify an empty derivation path.',
      );
    });

    it('throws if the derivation path is of depth 0 and not a single BIP-39 node', () => {
      expect(
        () => new BIP44Node({ derivationPath: [`bip32:0'`] as any }),
      ).toThrow(
        `Invalid HD path segment: The segment must consist of a single BIP-39 node for depths of ${MIN_BIP_44_DEPTH}. Received: "${[
          `bip32:0'`,
        ]}"`,
      );
    });

    it('throws if the key is neither a string nor a buffer', () => {
      expect(() => new BIP44Node({ depth: 0, key: {} as any })).toThrow(
        'Invalid key: Must be a Buffer or string if specified. Received: "object"',
      );
    });

    it('throws if the key is an invalid Buffer', () => {
      const invalidLengthBuffer = Buffer.alloc(63).fill(1);
      const zeroBuffer = Buffer.alloc(64);

      [invalidLengthBuffer, zeroBuffer].forEach((bufferKey) => {
        expect(() => new BIP44Node({ depth: 0, key: bufferKey })).toThrow(
          'Invalid buffer key: Must be a 64-byte, non-empty Buffer.',
        );
      });
    });

    it('throws if the key is an invalid string', () => {
      const hexInputs = [
        Buffer.alloc(64).toString('hex'),
        Buffer.alloc(63).fill(1).toString('hex'),
      ];

      [
        // Base64
        Buffer.alloc(64).toString('base64'),
        Buffer.alloc(63).fill(1).toString('base64'),

        // Hexadecimal
        ...hexInputs,
        ...hexInputs.map((input) => `0x${input}`),
      ].forEach((stringKey) => {
        expect(() => new BIP44Node({ depth: 0, key: stringKey })).toThrow(
          'Invalid string key: Must be a 64-byte hexadecimal or Base64 string.',
        );
      });
    });
  });

  describe('derive', () => {
    it('derives a child node', () => {
      const coinTypeNode = `bip32:40'`;
      const targetNode = new BIP44Node({
        derivationPath: [defaultBip39Node, BIP44PurposeNode, coinTypeNode],
      });

      const childNode = new BIP44Node({
        derivationPath: [defaultBip39Node, BIP44PurposeNode],
      }).derive([coinTypeNode]);

      expect(childNode).toMatchObject({
        depth: targetNode.depth,
        key: targetNode.key,
      });
    });

    it('throws if the parent node is already a leaf node', () => {
      expect(() =>
        new BIP44Node({
          derivationPath: [
            defaultBip39Node,
            BIP44PurposeNode,
            `bip32:3'`,
            `bip32:0'`,
            `bip32:0`,
            `bip32:0`,
          ],
        }).derive([`bip32:1`]),
      ).toThrow('Illegal operation: This HD tree node is already a leaf node.');
    });

    it('throws if the child derivation path is zero', () => {
      expect(() =>
        new BIP44Node({
          derivationPath: [
            defaultBip39Node,
            BIP44PurposeNode,
            `bip32:3'`,
            `bip32:0'`,
          ],
        }).derive([] as any),
      ).toThrow(
        'Invalid HD tree derivation path: Deriving a path of length 0 is not defined',
      );
    });
  });

  describe('toJSON', () => {
    it('returns a JSON-compatible representation of the node', () => {
      const node = new BIP44Node({
        derivationPath: [defaultBip39Node, BIP44PurposeNode, `bip32:60'`],
      });

      expect(typeof node.key).toStrictEqual('string');
      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(2);

      const nodeJson = node.toJSON();
      expect(nodeJson).toStrictEqual({
        depth: node.depth,
        key: node.key,
      });

      expect(JSON.parse(JSON.stringify(nodeJson))).toStrictEqual({
        depth: node.depth,
        key: node.key,
      });
    });
  });
});
