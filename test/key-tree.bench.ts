import { describe, bench } from 'vitest';

import fixtures from './fixtures';
import { secp256k1, ed25519, ed25519Bip32, SLIP10Node } from '../src';
import { deriveChildKey } from '../src/derivers/bip39';

describe('SLIP10Node', () => {
  describe('fromExtendedKey', () => {
    describe('secp256k1', async () => {
      const privateNode = await deriveChildKey({
        path: fixtures.local.seed,
        curve: secp256k1,
      });

      const publicNode = privateNode.neuter();

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

    describe('ed25519', async () => {
      const privateNode = await deriveChildKey({
        path: fixtures.local.seed,
        curve: ed25519,
      });

      const publicNode = privateNode.neuter();

      describe('from a JSON object', () => {
        bench('with a private key', async () => {
          await SLIP10Node.fromExtendedKey(privateNode.toJSON());
        });

        bench('with a public key', async () => {
          await SLIP10Node.fromExtendedKey(publicNode.toJSON());
        });
      });
    });

    describe('ed25519Bip32', async () => {
      const privateNode = await deriveChildKey({
        path: fixtures.local.seed,
        curve: ed25519Bip32,
      });

      const publicNode = privateNode.neuter();

      describe('from a JSON object', () => {
        bench('with a private key', async () => {
          await SLIP10Node.fromExtendedKey(privateNode.toJSON());
        });

        bench('with a public key', async () => {
          await SLIP10Node.fromExtendedKey(publicNode.toJSON());
        });
      });
    });
  });
});
