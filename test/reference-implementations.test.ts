import HdKeyring from 'eth-hd-keyring';
import { hdkey } from 'ethereumjs-wallet';
import { BIP44Node } from '../src/BIP44Node';
import { BIP44PurposeNode } from '../src/constants';
import { privateKeyToEthAddress } from '../src/derivers/bip32';
import { createKeyFromSeed } from '../src/derivers/bip39';
import { getBIP44AddressPathTuple, stripHexPrefix } from '../src/utils';
import fixtures from './fixtures';

describe('reference implementation tests', () => {
  describe('local', () => {
    describe('BIP44Node', () => {
      const { addresses, mnemonic } = fixtures.local;

      it('derives the expected keys', () => {
        // Ethereum coin type node
        const node = new BIP44Node({
          derivationPath: [`bip39:${mnemonic}`, BIP44PurposeNode, `bip32:60'`],
        });

        addresses.forEach((expectedAddress, index) => {
          const childNode = node.derive(
            getBIP44AddressPathTuple({ address_index: index }),
          );

          expect(
            privateKeyToEthAddress(childNode.keyBuffer).toString('hex'),
          ).toStrictEqual(expectedAddress);
        });
      });
    });

    describe('deriveKeyFromPath', () => {
      it.todo('derives the expected keys');
    });
  });

  describe('eth-hd-keyring', () => {
    describe('BIP44Node', () => {
      const { mnemonic } = fixtures['eth-hd-keyring'];

      it('derives the same keys as the reference implementation', async () => {
        const bip39Node = `bip39:${mnemonic}` as const;

        // Ethereum coin type node
        const node = new BIP44Node({
          derivationPath: [bip39Node, BIP44PurposeNode, `bip32:60'`],
        });

        const numberOfAccounts = 5;
        const ourAccounts = [];
        for (let i = 0; i < numberOfAccounts; i++) {
          ourAccounts.push(
            privateKeyToEthAddress(
              node.derive(getBIP44AddressPathTuple({ address_index: i }))
                .keyBuffer,
            ).toString('hex'),
          );
        }

        const hdKeyring = new HdKeyring({
          mnemonic,
          numberOfAccounts,
        });

        expect(await hdKeyring.getAccounts()).toStrictEqual(
          ourAccounts.map((account) => `0x${account}`),
        );
      });
    });

    describe('deriveKeyFromPath', () => {
      it.todo('derives the same keys as the reference implementation');
    });
  });

  describe('ethereumjs-wallet', () => {
    describe('BIP44Node', () => {
      const { sampleIndices, seed, path } = fixtures['ethereumjs-wallet'];

      it('derives the same keys as the reference implementation', () => {
        const seedKey = createKeyFromSeed(seed);

        const fixtureHd = hdkey.fromMasterSeed(seed);
        const childFixtureHd = fixtureHd.derivePath(path.theirs);
        const childFixtureHdKey = childFixtureHd.getWallet().getPrivateKey();

        const node = new BIP44Node({
          depth: 0,
          key: seedKey,
        }).derive(path.ours.tuple);

        expect(node.keyBuffer.slice(0, 32).toString('base64')).toStrictEqual(
          childFixtureHdKey.toString('base64'),
        );

        expect(
          privateKeyToEthAddress(node.keyBuffer).toString('hex'),
        ).toStrictEqual(
          stripHexPrefix(childFixtureHd.getWallet().getAddressString()),
        );

        sampleIndices.forEach((index) => {
          const ourAddress = privateKeyToEthAddress(
            node.derive([`bip32:${index}`]).keyBuffer,
          ).toString('hex');

          const theirAddress = stripHexPrefix(
            childFixtureHd.deriveChild(index).getWallet().getAddressString(),
          );

          expect(ourAddress).toStrictEqual(theirAddress);
        });
      });
    });

    describe('deriveKeyFromPath', () => {
      it.todo('derives the same keys as the reference implementation');
    });
  });
});
