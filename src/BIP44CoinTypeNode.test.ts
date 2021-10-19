import fixtures from '../test/fixtures';
import { BIP44CoinTypeNode } from './BIP44CoinTypeNode';
import { BIP44PurposeNode } from './constants';

const defaultBip39Node = `bip39:${fixtures.local.mnemonic}` as const;

describe('BIP44CoinTypeNode', () => {
  describe('constructor', () => {
    it('initializes a BIP44CoinTypeNode', () => {
      const node = new BIP44CoinTypeNode([
        defaultBip39Node,
        BIP44PurposeNode,
        `bip32:60'`,
      ]);
      const expectedCoinType = 60;
      const expectedPath = `m / bip32:44' / bip32:${expectedCoinType}'`;

      expect(node.coin_type).toStrictEqual(expectedCoinType);
      expect(node.depth).toStrictEqual(2);
      expect(node.key).toHaveLength(88);
      expect(node.path).toStrictEqual(expectedPath);

      expect(node.toJSON()).toStrictEqual({
        coin_type: expectedCoinType,
        depth: 2,
        key: node.key,
        path: expectedPath,
      });
    });
  });

  describe('deriveBIP44Address', () => {
    it.todo('derives an address key');
  });

  describe('toJSON', () => {
    it.todo('returns a JSON-compatible representation of the node');
  });
});

describe('deriveBIP44AddressKey', () => {
  it.todo('derives a BIP-44 address key');
});

describe('getBIP44AddressKeyDeriver', () => {
  it.todo('returns a BIP-44 address key deriver function');
});
