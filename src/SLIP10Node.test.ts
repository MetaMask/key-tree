import { secp256k1 } from './curves';
import { SLIP10Node } from './SLIP10Node';

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
  });
});
