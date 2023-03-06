import { bytesToHex, hexToBytes } from '@metamask/utils';
import { CURVE } from '@noble/secp256k1';

import fixtures from '../../test/fixtures';
import { BIP_32_HARDENED_OFFSET } from '../constants';
import { ed25519, secp256k1 } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import { hexStringToBytes } from '../utils';
import {
  deriveChildKey,
  privateAdd,
  privateKeyToEthAddress,
  publicKeyToEthAddress,
} from './bip32';
import { bip39MnemonicToMultipath, createBip39KeyFromSeed } from './bip39';

const privateAddFixtures = fixtures['secp256k1-node'].privateAdd;

describe('deriveChildKey', () => {
  describe('private key derivation', () => {
    it('handles invalid keys using BIP-32', async () => {
      const node = await SLIP10Node.fromDerivationPath({
        derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
        curve: 'secp256k1',
        specification: 'bip32',
      });

      // Simulate an invalid key once.
      jest.spyOn(secp256k1, 'isValidPrivateKey').mockReturnValueOnce(false);

      const childNode = await deriveChildKey({
        node,
        path: `0'`,
        curve: secp256k1,
        specification: 'bip32',
      });

      expect(childNode.index).toBe(BIP_32_HARDENED_OFFSET + 1);
      expect(childNode).toMatchInlineSnapshot(`
        Object {
          "chainCode": "0x7130d479bc9ce1cfee01198328193fadb76392927c3bd2094c23ff965c144014",
          "curve": "secp256k1",
          "depth": 1,
          "index": 2147483649,
          "masterFingerprint": 3293725253,
          "parentFingerprint": 3293725253,
          "privateKey": "0x457ab747ec683ff3288b73058a62a0a2192b7f449340e04c0d69d7b9789f6055",
          "publicKey": "0x04e59bdd93c7bbd052be1f50abfefde2b77f3c6988696cf7db879c2f794e20e10d7966a4350462760aafbce95b5a246ad563ef83f7f674a54ec606f209862a97f7",
          "specification": "bip32",
        }
      `);
    });

    it.each(fixtures.bip32InvalidPrivateKeys.keys)(
      'handles invalid keys using BIP-32 (test vectors)',
      async ({ path, privateKey, chainCode, index, depth }) => {
        const node = await createBip39KeyFromSeed(
          hexToBytes(fixtures.bip32InvalidPrivateKeys.hexSeed),
          secp256k1,
        );

        // Simulate an invalid key once.
        jest.spyOn(secp256k1, 'isValidPrivateKey').mockReturnValueOnce(false);

        const childNode = await node.derive(path.ours.tuple);
        expect(childNode.privateKey).toBe(privateKey);
        expect(childNode.chainCode).toBe(chainCode);
        expect(childNode.index).toBe(index);
        expect(childNode.depth).toBe(depth);
      },
    );

    it('handles invalid keys using SLIP-10', async () => {
      // TODO: Compare these results to reference implementations.

      const node = await SLIP10Node.fromDerivationPath({
        derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
        curve: 'secp256k1',
        specification: 'slip10',
      });

      // Simulate an invalid key once.
      jest.spyOn(secp256k1, 'isValidPrivateKey').mockReturnValueOnce(false);

      const childNode = await deriveChildKey({
        node,
        path: `0'`,
        curve: secp256k1,
        specification: 'slip10',
      });

      expect(childNode.index).toBe(BIP_32_HARDENED_OFFSET);
      expect(childNode).toMatchInlineSnapshot(`
        Object {
          "chainCode": "0x2dd86ecbca6c764e76448768e339b040ce56a29b7e690ddaa5bd38595c541faa",
          "curve": "secp256k1",
          "depth": 1,
          "index": 2147483648,
          "masterFingerprint": 3293725253,
          "parentFingerprint": 3293725253,
          "privateKey": "0x41d301d366bf9ff128ad00f9d1c9fcfd2646c87a543cf99ff73daee29f73bf5b",
          "publicKey": "0x045377ddaa9510b262f7469604478d9e377132eae8ab97b0c709f2250387c12f1e3e98c26f2ef0578131bf65b7eb543b55ed9f691709352ba82cb3245c16092abb",
          "specification": "slip10",
        }
      `);
    });

    it('throws the original error if the curve is ed25519', async () => {
      const node = await SLIP10Node.fromDerivationPath({
        derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
        curve: 'ed25519',
        specification: 'slip10',
      });

      // This should never be the case.
      const error = new Error('Unable to derive child key.');
      jest.spyOn(ed25519, 'getPublicKey').mockRejectedValueOnce(error);

      await expect(
        deriveChildKey({
          node,
          path: `0'`,
          curve: ed25519,
          specification: 'slip10',
        }),
      ).rejects.toThrow(error);
    });
  });

  describe('public key derivation', () => {
    it('handles invalid keys using BIP-32', async () => {
      // TODO: Compare these results to reference implementations.

      const node = await SLIP10Node.fromDerivationPath({
        derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
        curve: 'secp256k1',
        specification: 'bip32',
      }).then((privateNode) => privateNode.neuter());

      // Simulate an invalid key once.
      jest.spyOn(secp256k1, 'publicAdd').mockImplementationOnce(() => {
        throw new Error('Invalid key.');
      });

      const childNode = await deriveChildKey({
        node,
        path: `0`,
        curve: secp256k1,
        specification: 'bip32',
      });

      expect(childNode.index).toBe(1);
      expect(childNode).toMatchInlineSnapshot(`
        Object {
          "chainCode": "0x145e1cca88eec3c355707226a1fb87a91e27e18720d9d91c6555cfa307207dbe",
          "curve": "secp256k1",
          "depth": 1,
          "index": 1,
          "masterFingerprint": 3293725253,
          "parentFingerprint": 3293725253,
          "privateKey": undefined,
          "publicKey": "0x047e2329db2561e463f4acaefec0d1c89452592ab393552aaa2f3d1afcc93e03ba51fe19e3d994c4c00cc438fa33af2ba5dc41a7d969c6dcab0724411f52a6ade8",
          "specification": "bip32",
        }
      `);
    });

    it('handles invalid keys using SLIP-10', async () => {
      // TODO: Compare these results to reference implementations.

      const node = await SLIP10Node.fromDerivationPath({
        derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
        curve: 'secp256k1',
        specification: 'slip10',
      }).then((privateNode) => privateNode.neuter());

      // Simulate an invalid key once.
      jest.spyOn(secp256k1, 'publicAdd').mockImplementationOnce(() => {
        throw new Error('Invalid key.');
      });

      const childNode = await deriveChildKey({
        node,
        path: `0`,
        curve: secp256k1,
        specification: 'slip10',
      });

      expect(childNode.index).toBe(0);
      expect(childNode).toMatchInlineSnapshot(`
        Object {
          "chainCode": "0x03eebbe4707329e7da4aef868adb65f21bdc8712a86567b17a15ee4c3f01a57a",
          "curve": "secp256k1",
          "depth": 1,
          "index": 0,
          "masterFingerprint": 3293725253,
          "parentFingerprint": 3293725253,
          "privateKey": undefined,
          "publicKey": "0x04bc28203026c9fda2030f00ca592bdbe25392a106afae5205fa07dc4d77ecc61d21fa7a4bf21920abb52f56ae87f2d7b10d5db8d51229dea9c98c6b7982d514f9",
          "specification": "slip10",
        }
      `);
    });
  });

  it('throws an error if the specification is undefined', async () => {
    const node = await SLIP10Node.fromDerivationPath({
      derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
      curve: 'secp256k1',
    });

    await expect(
      deriveChildKey({
        node,
        path: `'bip32:0'`,
        curve: secp256k1,
        specification: undefined,
      }),
    ).rejects.toThrow(`Invalid specification: Must be specified.`);
  });

  it.each(['foo', 'bip-32', 'slip-10', 'BIP32', 'SLIP10'])(
    'throws an error if the specification is invalid',
    async (specification) => {
      const node = await SLIP10Node.fromDerivationPath({
        derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
        curve: 'secp256k1',
      });

      await expect(
        deriveChildKey({
          node,
          path: `'bip32:0'`,
          curve: secp256k1,
          // @ts-expect-error Invalid specification type.
          specification,
        }),
      ).rejects.toThrow(
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
        `Invalid specification: Must be one of bip32, slip10. Received "${specification}".`,
      );
    },
  );

  it('throws an error if the curve is ed25519 and the specification is bip32', async () => {
    const node = await SLIP10Node.fromDerivationPath({
      derivationPath: [bip39MnemonicToMultipath(fixtures.local.mnemonic)],
      curve: 'secp256k1',
    });

    await expect(
      deriveChildKey({
        node,
        path: `'bip32:0'`,
        curve: ed25519,
        specification: 'bip32',
      }),
    ).rejects.toThrow(
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      `Invalid specification: The ed25519 curve only supports "slip10".`,
    );
  });
});

describe('privateAdd', () => {
  const PRIVATE_KEY = hexStringToBytes(
    '51f34c9afc9d5b43e085688db58bb923c012bb07e42a8eaf18a8400aa9a167fb',
  );

  it.each(privateAddFixtures)(
    'adds a tweak to a private key',
    ({ privateKey, tweak, result }) => {
      const expected = hexStringToBytes(result);

      expect(
        privateAdd(
          hexStringToBytes(privateKey),
          hexStringToBytes(tweak),
          secp256k1,
        ),
      ).toStrictEqual(expected);
    },
  );

  it('throws if the tweak is larger than the curve order', () => {
    const tweak = hexStringToBytes(CURVE.n.toString(16));

    expect(() => privateAdd(PRIVATE_KEY, tweak, secp256k1)).toThrow(
      'Invalid tweak: Tweak is larger than the curve order.',
    );
  });

  it('throws if the result is invalid', () => {
    // n - 1
    const privateKey = hexStringToBytes(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
    );

    // 1
    const tweak = hexStringToBytes(
      '0000000000000000000000000000000000000000000000000000000000000001',
    );

    expect(() => privateAdd(privateKey, tweak, secp256k1)).toThrow(
      'Invalid private key or tweak: The resulting private key is invalid.',
    );
  });

  it.each([
    '0x7ebc0a630524c2d5ac55a98b8527a8ab2e842cd7b4037baadc463e597183408200',
    '0xa0a86d020f4c512b8639c38ecb9a3792f1575d3a4ad832e2523fd447c67170',
    '0x0efd64c97a920e71d90cf54589fb8a93',
    '0x1',
  ])('throws if the tweak is not 32 bytes long', (tweak) => {
    expect(() => privateAdd(PRIVATE_KEY, hexToBytes(tweak), secp256k1)).toThrow(
      'Invalid tweak: Tweak must be a non-zero 32-byte Uint8Array.',
    );
  });

  it('throws if the tweak is zero', () => {
    expect(() =>
      privateAdd(PRIVATE_KEY, new Uint8Array(32).fill(0), secp256k1),
    ).toThrow('Invalid tweak: Tweak must be a non-zero 32-byte Uint8Array.');
  });
});

describe('privateKeyToEthAddress', () => {
  it('returns the Ethereum address for a private key', () => {
    const { privateKey, address } = fixtures['ethereumjs-wallet'];

    expect(
      bytesToHex(privateKeyToEthAddress(hexStringToBytes(privateKey))),
    ).toBe(address);
  });

  it('throws for invalid private keys', () => {
    // @ts-expect-error Invalid public key type.
    expect(() => privateKeyToEthAddress('foo')).toThrow(
      'Invalid key: The key must be a 32-byte, non-zero Uint8Array.',
    );

    expect(() => privateKeyToEthAddress(new Uint8Array(31).fill(1))).toThrow(
      'Invalid key: The key must be a 32-byte, non-zero Uint8Array.',
    );
  });
});

describe('publicKeyToEthAddress', () => {
  it('returns the Ethereum address for a public key', () => {
    const { publicKey, address } = fixtures['ethereumjs-wallet'];

    expect(bytesToHex(publicKeyToEthAddress(hexStringToBytes(publicKey)))).toBe(
      address,
    );
  });

  it('throws for invalid public keys', () => {
    // @ts-expect-error Invalid public key type.
    expect(() => publicKeyToEthAddress('foo')).toThrow(
      'Invalid key: The key must be a 65-byte, non-zero Uint8Array.',
    );

    expect(() => publicKeyToEthAddress(new Uint8Array(64).fill(1))).toThrow(
      'Invalid key: The key must be a 65-byte, non-zero Uint8Array.',
    );
  });
});
