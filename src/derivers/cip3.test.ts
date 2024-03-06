import { bytesToHex, hexToBytes } from '@metamask/utils';

import fixtures from '../../test/fixtures';
import { BIP_32_HARDENED_OFFSET } from '../constants';
import { ed25519Bip32 } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import {
  deriveChainCode,
  deriveChildKey,
  derivePrivateKey,
  derivePublicKey,
} from './cip3';

const fixtureNodeToParentNode = (
  fixtureNode: typeof fixtures.cip3[number]['nodes'][keyof typeof fixtures.cip3[number]['nodes']],
) => ({
  privateKeyBytes: hexToBytes(fixtureNode.privateKey),
  publicKeyBytes: hexToBytes(fixtureNode.publicKey),
  chainCodeBytes: hexToBytes(fixtureNode.chainCode),
});

describe('Cip3', () => {
  fixtures.cip3.forEach((fixture) => {
    describe('derivePrivate', () => {
      const { bip39Node, purposeNode, coinTypeNode, accountNode, changeNode } =
        fixture.nodes;
      it('derives hardened private key 1', async () => {
        const privateKey = await derivePrivateKey({
          parentNode: fixtureNodeToParentNode(bip39Node),
          isHardened: true,
          childIndex: purposeNode.index - BIP_32_HARDENED_OFFSET,
        });
        expect(bytesToHex(privateKey)).toBe(purposeNode.privateKey);
      });
      it('derives hardened private key', async () => {
        const privateKey = await derivePrivateKey({
          parentNode: fixtureNodeToParentNode(purposeNode),
          isHardened: true,
          childIndex: coinTypeNode.index - BIP_32_HARDENED_OFFSET,
        });
        expect(bytesToHex(privateKey)).toBe(coinTypeNode.privateKey);
      });
      it('derives non-hardened private key', async () => {
        const privateKey = await derivePrivateKey({
          parentNode: fixtureNodeToParentNode(accountNode),
          isHardened: false,
          childIndex: changeNode.index,
        });
        expect(bytesToHex(privateKey)).toBe(changeNode.privateKey);
      });
    });

    describe('deriveChainCode', () => {
      const { bip39Node, purposeNode, accountNode, changeNode } = fixture.nodes;
      it('derives hardened chainCode key', async () => {
        const chainCode = await deriveChainCode({
          parentNode: fixtureNodeToParentNode(bip39Node),
          isHardened: true,
          childIndex: purposeNode.index - BIP_32_HARDENED_OFFSET,
        });
        expect(bytesToHex(chainCode)).toBe(purposeNode.chainCode);
      });
      it('derives non-hardened private key', async () => {
        const chainCode = await deriveChainCode({
          parentNode: fixtureNodeToParentNode(accountNode),
          isHardened: false,
          childIndex: changeNode.index,
        });
        expect(bytesToHex(chainCode)).toBe(changeNode.chainCode);
      });
    });

    describe('derivePublicKey', () => {
      const { changeNode, addressIndexNode } = fixture.nodes;
      it('derives public key', async () => {
        const chainCode = await derivePublicKey({
          parentNode: fixtureNodeToParentNode(changeNode),
          childIndex: addressIndexNode.index,
          isHardened: false,
          curve: ed25519Bip32,
        });
        expect(bytesToHex(chainCode)).toBe(addressIndexNode.publicKey);
      });
    });

    describe('deriveChildKey', () => {
      const [purpose, coinType, accountIndex, change, addressIndex] =
        fixture.derivationPath;
      const {
        bip39Node,
        purposeNode,
        coinTypeNode,
        accountNode,
        changeNode,
        addressIndexNode,
      } = fixture.nodes;

      it('derives purpose node', async () => {
        const purposeNodeRes = await deriveChildKey({
          node: await SLIP10Node.fromJSON(bip39Node),
          path: purpose,
          curve: ed25519Bip32,
        });

        expect(JSON.stringify(purposeNodeRes)).toBe(
          JSON.stringify(purposeNode),
        );
      });
      it('derives coinType node', async () => {
        const coinTypeNodeRes = await deriveChildKey({
          node: await SLIP10Node.fromJSON(purposeNode),
          path: coinType,
          curve: ed25519Bip32,
        });

        expect(JSON.stringify(coinTypeNodeRes)).toBe(
          JSON.stringify(coinTypeNode),
        );
      });
      it('derives account node', async () => {
        const accountNodeRes = await deriveChildKey({
          node: await SLIP10Node.fromJSON(coinTypeNode),
          path: accountIndex,
          curve: ed25519Bip32,
        });

        expect(JSON.stringify(accountNodeRes)).toBe(
          JSON.stringify(accountNode),
        );
      });
      it('derives change node', async () => {
        const changeNodeRes = await deriveChildKey({
          node: await SLIP10Node.fromJSON(accountNode),
          path: change,
          curve: ed25519Bip32,
        });

        expect(JSON.stringify(changeNodeRes)).toBe(JSON.stringify(changeNode));
      });
      it('derives addressIndex node', async () => {
        const addressIndexNodeRes = await deriveChildKey({
          node: await SLIP10Node.fromJSON(changeNode),
          path: addressIndex,
          curve: ed25519Bip32,
        });

        expect(JSON.stringify(addressIndexNodeRes)).toBe(
          JSON.stringify(addressIndexNode),
        );
      });
    });
  });
});
