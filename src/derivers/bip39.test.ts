import {
  assert,
  bigIntToBytes,
  concatBytes,
  hexToBytes,
} from '@metamask/utils';
import * as hmacModule from '@noble/hashes/hmac';

import { secp256k1 } from '../curves';
import { createBip39KeyFromSeed } from './bip39';

describe('createBip39KeyFromSeed', () => {
  const RANDOM_SEED = hexToBytes(
    '0xea82e6ee9d319c083007d0b011a37b0e480ae02417a988ac90355abd53cd04fc',
  );

  it('throws if the private key is zero', async () => {
    // Mock the hmac function to return a zero private key.
    jest.spyOn(hmacModule, 'hmac').mockImplementation(() => new Uint8Array(64));

    await expect(
      createBip39KeyFromSeed(RANDOM_SEED, secp256k1),
    ).rejects.toThrow(
      'Invalid private key: The private key must larger than 0 and less than the curve order.',
    );
  });

  it.each([
    bigIntToBytes(secp256k1.curve.n),
    concatBytes([secp256k1.curve.n + BigInt(1)]),
  ])(
    'throws if the private key is larger than or equal to the curve order',
    async (privateKey) => {
      // For this test to be effective, the private key must be 32 bytes.
      assert(privateKey.length === 32);

      // Mock the hmac function to return a private key larger than the curve order.
      jest
        .spyOn(hmacModule, 'hmac')
        .mockImplementation(() =>
          concatBytes([privateKey, new Uint8Array(32)]),
        );

      await expect(
        createBip39KeyFromSeed(RANDOM_SEED, secp256k1),
      ).rejects.toThrow(
        'Invalid private key: The private key must larger than 0 and less than the curve order.',
      );
    },
  );
});
