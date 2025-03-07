import { describe, bench } from 'vitest';

import fixtures from './fixtures';
import { secp256k1, SLIP10Node } from '../src';
import { deriveChildKey } from '../src/derivers/bip39';

describe('SLIP10Node', async () => {
  const privateNode = await deriveChildKey({
    path: fixtures.local.seed,
    curve: secp256k1,
  });

  const publicNode = privateNode.neuter();

  describe('fromExtendedKey', () => {
    describe('from a JSON object', () => {
      bench('with a private key', async () => {
        await SLIP10Node.fromExtendedKey(privateNode.toJSON());
      });

      bench('with a public key', async () => {
        await SLIP10Node.fromExtendedKey(publicNode.toJSON());
      });
    });

    describe('from an extended key', () => {
      bench('with a private key', async () => {
        await SLIP10Node.fromExtendedKey(privateNode.extendedKey);
      });

      bench('with a public key', async () => {
        await SLIP10Node.fromExtendedKey(publicNode.extendedKey);
      });
    });
  });
});
