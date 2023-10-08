import type { SLIP10Node, HDPathTuple } from '../src';
import { BIP44Node, BIP44PurposeNodeToken } from '../src';
import { ed25519, secp256k1 } from '../src/curves';
import { deriveKeyFromPath } from '../src/derivation';
import { createBip39KeyFromSeed } from '../src/derivers/bip39';
import {
  getBIP44CoinTypeToAddressPathTuple,
  hexStringToBytes,
} from '../src/utils';
import fixtures from './fixtures';

describe('reference implementation tests', () => {
  describe('local', () => {
    const { addresses, mnemonic } = fixtures.local;
    const mnemonicBip39Node = `bip39:${mnemonic}` as const;

    describe('BIP44Node', () => {
      it('derives the expected keys', () => {
        // Ethereum coin type node
        const node = BIP44Node.fromDerivationPath({
          derivationPath: [
            mnemonicBip39Node,
            BIP44PurposeNodeToken,
            `bip32:60'`,
          ],
        });

        for (let index = 0; index < addresses.length; index++) {
          const expectedAddress = addresses[index];
          const childNode = node.derive(
            getBIP44CoinTypeToAddressPathTuple({ address_index: index }),
          );

          expect(childNode.address).toStrictEqual(expectedAddress);
        }
      });
    });

    describe('deriveKeyFromPath', () => {
      it('derives the expected keys', () => {
        // Ethereum coin type key
        const node = deriveKeyFromPath({
          path: [mnemonicBip39Node, BIP44PurposeNodeToken, `bip32:60'`],
          curve: 'secp256k1',
        });

        for (let index = 0; index < addresses.length; index++) {
          const expectedAddress = addresses[index];
          const { address } = deriveKeyFromPath({
            path: getBIP44CoinTypeToAddressPathTuple({ address_index: index }),
            node,
          });

          expect(address).toStrictEqual(expectedAddress);
        }
      });
    });
  });

  describe('eth-hd-keyring', () => {
    const { mnemonic, addresses } = fixtures['eth-hd-keyring'];
    const mnemonicBip39Node = `bip39:${mnemonic}` as const;

    describe('BIP44Node', () => {
      it('derives the same keys as the reference implementation', () => {
        // Ethereum coin type node
        const node = BIP44Node.fromDerivationPath({
          derivationPath: [
            mnemonicBip39Node,
            BIP44PurposeNodeToken,
            `bip32:60'`,
          ],
        });

        const numberOfAccounts = 5;
        for (let i = 0; i < numberOfAccounts; i++) {
          const path = getBIP44CoinTypeToAddressPathTuple({ address_index: i });
          const { address } = node.derive(path);

          expect(address).toBe(addresses[i]);
        }
      });

      it('derives the same keys as the reference implementation using public key derivation', () => {
        // Ethereum coin type node
        const node = BIP44Node.fromDerivationPath({
          derivationPath: [
            mnemonicBip39Node,
            BIP44PurposeNodeToken,
            `bip32:60'`,
          ],
        });

        const numberOfAccounts = 5;
        for (let i = 0; i < numberOfAccounts; i++) {
          const [account, change, index] = getBIP44CoinTypeToAddressPathTuple({
            address_index: i,
          });
          const parentNode = node.derive([account, change]);

          const { address } = parentNode.neuter().derive([index]);

          expect(address).toBe(addresses[i]);
        }
      });
    });

    describe('deriveKeyFromPath', () => {
      it('derives the same keys as the reference implementation', () => {
        // Ethereum coin type key
        const node = deriveKeyFromPath({
          path: [mnemonicBip39Node, BIP44PurposeNodeToken, `bip32:60'`],
          curve: 'secp256k1',
        });

        const numberOfAccounts = 5;
        const ourAccounts = [];
        for (let i = 0; i < numberOfAccounts; i++) {
          ourAccounts.push(
            deriveKeyFromPath({
              path: getBIP44CoinTypeToAddressPathTuple({ address_index: i }),
              node,
            }).address,
          );
        }

        expect(addresses).toStrictEqual(ourAccounts);
      });
    });
  });

  describe('ethereumjs-wallet', () => {
    const { sampleAddressIndices, hexSeed, privateKey, address, path } =
      fixtures['ethereumjs-wallet'];
    const seed = hexStringToBytes(hexSeed);

    describe('BIP44Node', () => {
      it('derives the same keys as the reference implementation', () => {
        const parentNode = createBip39KeyFromSeed(seed, secp256k1);
        const node = parentNode.derive(path.ours.tuple);

        expect(node.privateKey).toStrictEqual(privateKey);
        expect(node.address).toStrictEqual(address);

        for (const { index, address: theirAddress } of sampleAddressIndices) {
          const ourAddress = node.derive([`bip32:${index}`]).address;

          expect(ourAddress).toStrictEqual(theirAddress);
        }
      });

      it('derives the same keys as the reference implementation using public key derivation', () => {
        const parentNode = createBip39KeyFromSeed(seed, secp256k1);
        const node = parentNode.derive(path.ours.tuple);

        expect(node.privateKey).toStrictEqual(privateKey);
        expect(node.address).toStrictEqual(address);

        for (const { index, address: theirAddress } of sampleAddressIndices) {
          const ourAddress = node.neuter().derive([`bip32:${index}`]).address;

          expect(ourAddress).toStrictEqual(theirAddress);
        }
      });
    });

    describe('deriveKeyFromPath', () => {
      it('derives the same keys as the reference implementation', () => {
        const node = createBip39KeyFromSeed(seed, secp256k1);
        const childNode = deriveKeyFromPath({
          path: path.ours.tuple,
          node,
        });

        expect(childNode.privateKey).toStrictEqual(privateKey);
        expect(childNode.address).toStrictEqual(address);

        for (const { index, address: theirAddress } of sampleAddressIndices) {
          const childChildNode = deriveKeyFromPath({
            path: [`bip32:${index}`],
            node: childNode,
          });

          expect(childChildNode.address).toStrictEqual(theirAddress);
        }
      });
    });
  });

  describe('BIP-32 specification test vectors', () => {
    const vectors = fixtures.bip32;

    // We only test the BIP-32 vectors with deriveKeyFromPath, since not all
    // paths are BIP-44 compatible.
    describe('deriveKeyFromPath', () => {
      it('derives the test vector keys', () => {
        for (const vector of vectors) {
          const seed = hexStringToBytes(vector.hexSeed);
          const node = createBip39KeyFromSeed(seed, secp256k1);

          for (const keyObj of vector.keys) {
            const { path, privateKey } = keyObj;

            let targetNode: SLIP10Node;

            // If the path is empty, use the master node
            if (path.ours.string === '') {
              targetNode = node;
            } else {
              targetNode = deriveKeyFromPath({
                path: path.ours.tuple as HDPathTuple,
                node,
              });
            }

            expect(targetNode.privateKey).toStrictEqual(privateKey);
          }
        }
      });
    });
  });

  describe('ed25519', () => {
    describe('SLIP-10', () => {
      const vectors = fixtures.ed25519.slip10;

      describe('deriveKeyFromPath', () => {
        it('derives the test vector keys', () => {
          for (const { hexSeed, keys } of vectors) {
            const node = createBip39KeyFromSeed(
              hexStringToBytes(hexSeed),
              ed25519,
            );

            for (const { path, privateKey, publicKey } of keys) {
              let targetNode: SLIP10Node;
              if (path.ours.string === '') {
                targetNode = node;
              } else {
                targetNode = deriveKeyFromPath({
                  path: path.ours.tuple,
                  node,
                });
              }

              expect(targetNode.privateKey).toBe(privateKey);
              expect(targetNode.publicKey).toBe(publicKey);
            }
          }
        });
      });
    });

    describe('ed25519-hd-key', () => {
      const { sampleKeyIndices, hexSeed, privateKey, path } =
        fixtures.ed25519['ed25519-hd-key'];
      const seed = hexStringToBytes(hexSeed);

      describe('SLIP10Node', () => {
        it('derives the same keys as the reference implementation', () => {
          // Ethereum coin type node
          const parentNode = createBip39KeyFromSeed(seed, ed25519);
          const node = parentNode.derive(path.ours.tuple);

          expect(node.privateKey).toStrictEqual(privateKey);

          for (const {
            index,
            privateKey: theirPrivateKey,
            publicKey: theirPublicKey,
          } of sampleKeyIndices) {
            const childNode = node.derive([`slip10:${index}'`]);

            expect(childNode.privateKey).toStrictEqual(theirPrivateKey);
            expect(childNode.publicKey).toStrictEqual(theirPublicKey);
          }
        });
      });

      describe('deriveKeyFromPath', () => {
        it('derives the same keys as the reference implementation', () => {
          // Ethereum coin type key
          const node = createBip39KeyFromSeed(seed, ed25519);
          const childNode = deriveKeyFromPath({
            path: [`slip10:44'`, `slip10:0'`, `slip10:0'`, `slip10:1'`],
            node,
          });

          for (const {
            index,
            privateKey: theirPrivateKey,
          } of sampleKeyIndices) {
            const { privateKey: ourPrivateKey } = deriveKeyFromPath({
              path: [`slip10:${index}'`],
              node: childNode,
            });

            expect(ourPrivateKey).toStrictEqual(theirPrivateKey);
          }
        });
      });
    });
  });
});
