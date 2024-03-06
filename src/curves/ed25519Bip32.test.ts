import { bytesToHex, hexToBytes } from '@metamask/utils';

import { ed25519Bip32 } from '.';
import fixtures from '../../test/fixtures';

describe('getPublicKey', () => {
  fixtures.cip3Icarus.forEach((fixture) => {
    Object.values(fixture.nodes).forEach((node) => {
      it(`returns correct public key from private key`, async () => {
        const publicKey = await ed25519Bip32.getPublicKey(
          hexToBytes(node.privateKey),
        );

        expect(bytesToHex(publicKey)).toBe(node.publicKey);
      });
    });
  });
});

describe('publicAdd', () => {
  it(`returns correct public key from private key`, async () => {
    const _publicKey = hexToBytes(
      fixtures.cip3Icarus[0].nodes.bip39Node.publicKey,
    );
    const _tweak = hexToBytes(
      fixtures.cip3Icarus[0].nodes.purposeNode.publicKey,
    );
    const added = ed25519Bip32.publicAdd(_publicKey, _tweak);

    expect(bytesToHex(added)).toBe(
      '0xf78d2a445afe9c961ac196fbac282b499d9ab6bbe8801354ee06fc22d46503e2',
    );
  });
});
