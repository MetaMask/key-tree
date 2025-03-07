import { describe, bench } from 'vitest';

import fixtures from './fixtures';
import {
  secp256k1,
  ed25519,
  ed25519Bip32,
  SLIP10Node,
  mnemonicPhraseToBytes,
} from '../src';
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

  describe('fromDerivationPath', () => {
    describe('secp256k1', async () => {
      bench('with a string mnemonic phrase', async () => {
        await SLIP10Node.fromDerivationPath({
          derivationPath: [`bip39:${fixtures.local.mnemonic}`],
          curve: 'secp256k1',
        });
      });

      bench('with a Uint8Array mnemonic phrase', async () => {
        await SLIP10Node.fromDerivationPath({
          derivationPath: [mnemonicPhraseToBytes(fixtures.local.mnemonic)],
          curve: 'secp256k1',
        });
      });
    });

    describe('ed25519', async () => {
      bench('with a string mnemonic phrase', async () => {
        await SLIP10Node.fromDerivationPath({
          derivationPath: [`bip39:${fixtures.local.mnemonic}`],
          curve: 'ed25519',
        });
      });

      bench('with a Uint8Array mnemonic phrase', async () => {
        await SLIP10Node.fromDerivationPath({
          derivationPath: [mnemonicPhraseToBytes(fixtures.local.mnemonic)],
          curve: 'ed25519',
        });
      });
    });

    describe('ed25519Bip32', async () => {
      bench('with a string mnemonic phrase', async () => {
        await SLIP10Node.fromDerivationPath({
          derivationPath: [`bip39:${fixtures.local.mnemonic}`],
          curve: 'ed25519Bip32',
        });
      });

      bench('with a Uint8Array mnemonic phrase', async () => {
        await SLIP10Node.fromDerivationPath({
          derivationPath: [mnemonicPhraseToBytes(fixtures.local.mnemonic)],
          curve: 'ed25519Bip32',
        });
      });
    });

    describe('deriving a child key', () => {
      bench(
        'secp256k1',
        async () => {
          await SLIP10Node.fromDerivationPath({
            derivationPath: [
              `bip39:${fixtures.local.mnemonic}`,
              `bip32:0'`,
              `bip32:0'`,
            ],
            curve: 'secp256k1',
          });
        },
        { time: 2000, iterations: 5 },
      );

      bench(
        'ed25519',
        async () => {
          await SLIP10Node.fromDerivationPath({
            derivationPath: [
              `bip39:${fixtures.local.mnemonic}`,
              `slip10:0'`,
              `slip10:0'`,
            ],
            curve: 'ed25519',
          });
        },
        { time: 2000, iterations: 5 },
      );

      bench(
        'ed25519Bip32',
        async () => {
          await SLIP10Node.fromDerivationPath({
            derivationPath: [
              `bip39:${fixtures.local.mnemonic}`,
              `cip3:0'`,
              `cip3:0'`,
            ],
            curve: 'ed25519Bip32',
          });
        },
        { time: 2000, iterations: 5 },
      );
    });
  });
});
