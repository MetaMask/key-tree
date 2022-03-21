import fixtures from '../test/fixtures';
import { secp256k1 } from './curves';
import { SLIP10Node } from './SLIP10Node';
import { BIP44PurposeNodeToken } from './constants';

const defaultBip39NodeToken = `bip39:${fixtures.local.mnemonic}` as const;

describe('SLIP10Node', () => {
  describe('create', () => {
    it('throws if the depth is invalid', async () => {
      const validBufferKey = Buffer.alloc(64).fill(1);
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
        await expect(() =>
          SLIP10Node.create({
            depth: input as any,
            key: validBufferKey,
            curve: secp256k1,
          }),
        ).rejects.toThrow(
          `Invalid HD tree path depth: The depth must be a positive integer. Received: "${input}"`,
        );
      }
    });

    it('throws if the derivation path is empty', async () => {
      await expect(() =>
        SLIP10Node.create({ derivationPath: [] as any, curve: secp256k1 }),
      ).rejects.toThrow(
        'Invalid derivation path: May not specify an empty derivation path.',
      );
    });

    it('throws an error if attempting to modify the fields of a node', async () => {
      const node: any = await SLIP10Node.create({
        derivationPath: [
          defaultBip39NodeToken,
          BIP44PurposeNodeToken,
          `bip32:60'`,
        ],
        curve: secp256k1,
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
  });
});
