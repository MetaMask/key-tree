import {
  getBIP32NodeToken,
  getBIP44ChangePathString,
  getBIP44CoinTypePathString,
  getBIP44CoinTypeToAddressPathTuple,
  getHardenedBIP32NodeToken,
  getUnhardenedBIP32NodeToken,
  isValidBufferKey,
  nullableHexStringToBuffer,
  getBuffer,
  getFingerprint,
  hexStringToBuffer,
} from './utils';

import { BIP44Node } from './BIP44Node';

describe('getBIP44CoinTypePathString', () => {
  it('returns a BIP-44 coin type path string', () => {
    expect(getBIP44CoinTypePathString(0)).toBe(`m / bip32:44' / bip32:0'`);
    expect(getBIP44CoinTypePathString(1)).toBe(`m / bip32:44' / bip32:1'`);
    expect(getBIP44CoinTypePathString(1000)).toBe(
      `m / bip32:44' / bip32:1000'`,
    );
  });

  it('validates the index', () => {
    expect(() => getBIP44CoinTypePathString(-1)).toThrow(
      'Invalid BIP-32 index: Must be a non-negative integer.',
    );
  });
});

describe('getBIP44ChangePathString', () => {
  const coinTypePath = getBIP44CoinTypePathString(1);

  it('returns a BIP-44 change path string (default values)', () => {
    expect(getBIP44ChangePathString(coinTypePath, {})).toBe(
      `${coinTypePath} / bip32:0' / bip32:0`,
    );
  });

  it('returns a BIP-44 change path string (custom change)', () => {
    expect(getBIP44ChangePathString(coinTypePath, { change: 1 })).toBe(
      `${coinTypePath} / bip32:0' / bip32:1`,
    );
  });

  it('returns a BIP-44 change path string (custom account)', () => {
    expect(getBIP44ChangePathString(coinTypePath, { account: 1 })).toBe(
      `${coinTypePath} / bip32:1' / bip32:0`,
    );
  });

  it('returns a BIP-44 change path string (custom change, custom account)', () => {
    expect(
      getBIP44ChangePathString(coinTypePath, { account: 2, change: 3 }),
    ).toBe(`${coinTypePath} / bip32:2' / bip32:3`);
  });

  it('validates the index', () => {
    expect(() =>
      getBIP44ChangePathString(coinTypePath, { account: -1 }),
    ).toThrow('Invalid BIP-32 index: Must be a non-negative integer.');
  });
});

describe('getBIP44CoinTypeToAddressPathTuple', () => {
  it('returns a BIP-44 coin type as address path tuple (default values)', () => {
    expect(
      getBIP44CoinTypeToAddressPathTuple({ address_index: 0 }),
    ).toStrictEqual([`bip32:0'`, `bip32:0`, `bip32:0`]);
  });

  it('returns a BIP-44 coin type as address path tuple (custom address_index)', () => {
    expect(
      getBIP44CoinTypeToAddressPathTuple({ address_index: 1 }),
    ).toStrictEqual([`bip32:0'`, `bip32:0`, `bip32:1`]);
  });

  it('returns a BIP-44 coin type as address path tuple (custom change, hardened address_index)', () => {
    expect(
      getBIP44CoinTypeToAddressPathTuple({
        change: 1,
        address_index: { index: 2, hardened: true },
      }),
    ).toStrictEqual([`bip32:0'`, `bip32:1`, `bip32:2'`]);
  });

  it('returns a BIP-44 coin type as address path tuple (custom account, hardened change and address_index)', () => {
    expect(
      getBIP44CoinTypeToAddressPathTuple({
        account: 1,
        change: { index: 2, hardened: true },
        address_index: { index: 3, hardened: true },
      }),
    ).toStrictEqual([`bip32:1'`, `bip32:2'`, `bip32:3'`]);
  });

  it('validates the index', () => {
    expect(() =>
      getBIP44CoinTypeToAddressPathTuple({ address_index: -1 }),
    ).toThrow('Invalid BIP-32 index: Must be a non-negative integer.');
  });
});

describe('getHardenedBIP32NodeToken', () => {
  it('returns a hardened BIP-32 node token', () => {
    expect(getHardenedBIP32NodeToken(0)).toBe(`bip32:0'`);
    expect(getHardenedBIP32NodeToken(1)).toBe(`bip32:1'`);
    expect(getHardenedBIP32NodeToken(1000)).toBe(`bip32:1000'`);
  });

  it('validates the index', () => {
    expect(() => getHardenedBIP32NodeToken(-1)).toThrow(
      'Invalid BIP-32 index: Must be a non-negative integer.',
    );
  });
});

describe('getUnhardenedBIP32NodeToken', () => {
  it('returns an unhardened BIP-32 node token', () => {
    expect(getUnhardenedBIP32NodeToken(0)).toBe(`bip32:0`);
    expect(getUnhardenedBIP32NodeToken(1)).toBe(`bip32:1`);
    expect(getUnhardenedBIP32NodeToken(1000)).toBe(`bip32:1000`);
  });

  it('validates the index', () => {
    expect(() => getUnhardenedBIP32NodeToken(-1)).toThrow(
      'Invalid BIP-32 index: Must be a non-negative integer.',
    );
  });
});

describe('getBIP32NodeToken', () => {
  it('returns a BIP-32 node token (normal index)', () => {
    expect(getBIP32NodeToken(1)).toBe(`bip32:1`);
  });

  it('returns a BIP-32 node token (hardened index)', () => {
    expect(getBIP32NodeToken({ index: 1, hardened: true })).toBe(`bip32:1'`);
  });

  it('validates the index', () => {
    expect(() => getBIP32NodeToken(-1)).toThrow(
      'Invalid BIP-32 index: Must be a non-negative integer.',
    );

    // @ts-expect-error Invalid type.
    expect(() => getBIP32NodeToken({})).toThrow(
      'Invalid BIP-32 index: Must be an object containing the index and whether it is hardened.',
    );
  });
});

describe('nullableHexStringToBuffer', () => {
  it('returns a buffer for a hexadecimal string', () => {
    expect(nullableHexStringToBuffer('1234')).toStrictEqual(
      Buffer.from('1234', 'hex'),
    );
  });

  it('returns a buffer for a 0x-prefixed hexadecimal string', () => {
    expect(nullableHexStringToBuffer('0x1234')).toStrictEqual(
      Buffer.from('1234', 'hex'),
    );
  });

  it('returns undefined when passed undefined', () => {
    expect(nullableHexStringToBuffer(undefined)).toBeUndefined();
  });
});

describe('isValidBufferKey', () => {
  it('checks the buffer length', () => {
    expect(isValidBufferKey(Buffer.alloc(32).fill(1), 32)).toBe(true);
    expect(isValidBufferKey(Buffer.alloc(31).fill(1), 32)).toBe(false);
  });

  it('checks if the buffer has at least one non-zero byte', () => {
    expect(isValidBufferKey(Buffer.alloc(32).fill(1), 32)).toBe(true);
    expect(isValidBufferKey(Buffer.alloc(32).fill(0), 32)).toBe(false);
  });
});

describe('getBuffer', () => {
  it('returns a buffer for a hexadecimal string', () => {
    expect(getBuffer('0x1234', 2)).toStrictEqual(hexStringToBuffer('1234'));
    expect(getBuffer('1234', 2)).toStrictEqual(hexStringToBuffer('1234'));
  });

  it('returns the same buffer if a buffer is passed', () => {
    const buffer = hexStringToBuffer('1234');
    expect(getBuffer(buffer, 2)).toBe(buffer);
  });

  it('throws if the length is invalid', () => {
    expect(() => getBuffer('1234', 1)).toThrow(
      'Invalid value: Must be a non-zero 1-byte buffer.',
    );

    expect(() => getBuffer(hexStringToBuffer('1234'), 1)).toThrow(
      'Invalid value: Must be a non-zero 1-byte buffer.',
    );
  });
});

describe('getFingerprint', () => {
  it('returns the fingerprint for a compressed public key', async () => {
    const node = await BIP44Node.fromExtendedKey(
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    );

    expect(getFingerprint(node.compressedPublicKeyBuffer)).toBe(2391500305);
  });

  it('throws if the public key is not a valid buffer', async () => {
    expect(() => getFingerprint(Buffer.alloc(33).fill(0))).toThrow(
      'Invalid public key: The key must be a 33-byte, non-zero Buffer.',
    );

    expect(() => getFingerprint(Buffer.alloc(65).fill(1))).toThrow(
      'Invalid public key: The key must be a 33-byte, non-zero Buffer.',
    );
  });
});
