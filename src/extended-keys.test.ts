import {
  decodeExtendedKey,
  encodeExtendedKey,
  ExtendedKey,
  PRIVATE_KEY_VERSION,
  PUBLIC_KEY_VERSION,
} from './extended-keys';
import { hexStringToBuffer } from './utils';

describe('decodeExtendedKey', () => {
  it('decodes an extended public key', () => {
    const extendedKey =
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';

    expect(decodeExtendedKey(extendedKey)).toStrictEqual({
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      chainCode: hexStringToBuffer(
        '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
      ),
      publicKey: hexStringToBuffer(
        '0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281',
      ),
      version: PUBLIC_KEY_VERSION,
    });
  });

  it('decodes an extended private key', () => {
    const extendedKey =
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';

    expect(decodeExtendedKey(extendedKey)).toStrictEqual({
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      chainCode: hexStringToBuffer(
        '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
      ),
      privateKey: hexStringToBuffer(
        'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
      ),
      version: PRIVATE_KEY_VERSION,
    });
  });
});

describe('encodeExtendedKey', () => {
  it('encodes an extended public key', () => {
    const extendedKey: ExtendedKey = {
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      chainCode: hexStringToBuffer(
        '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
      ),
      publicKey: hexStringToBuffer(
        '0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281',
      ),
      version: PUBLIC_KEY_VERSION,
    };

    expect(encodeExtendedKey(extendedKey)).toBe(
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
    );
  });

  it('encodes an extended private key', () => {
    const extendedKey: ExtendedKey = {
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      chainCode: hexStringToBuffer(
        '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
      ),
      privateKey: hexStringToBuffer(
        'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
      ),
      version: PRIVATE_KEY_VERSION,
    };

    expect(encodeExtendedKey(extendedKey)).toBe(
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    );
  });
});
