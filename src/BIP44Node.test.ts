import crypto from 'crypto';
import { hdkey } from 'ethereumjs-wallet';
import { BIP44Node } from './BIP44Node';
import { getBIP44AddressKeyDeriver } from './BIP44CoinTypeNode';
import { privateKeyToEthAddress } from './derivers/bip32';
import { base64StringToBuffer } from './utils';

describe('BIP44Node', () => {
  describe('BIP44Node.constructor', () => {
    it('initializes a new node', () => {
      const mnemonic =
        'romance hurry grit huge rifle ordinary loud toss sound congress upset twist';

      const bip39Node = `bip39:${mnemonic}` as const;

      // ethereum coin type
      const node = new BIP44Node({
        depth: 2,
        derivationPath: [bip39Node, `bip32:44'`, `bip32:60'`],
      });

      expect(node.key).toHaveLength(88);
      expect(node.depth).toStrictEqual(2);
      expect(node.toJSON()).toStrictEqual({
        depth: 2,
        key: node.key,
      });
    });
  });

  describe('BIP44Node.key', () => {
    it.todo('returns the node key as a Base64 string');
  });

  describe('BIP44Node.toJSON', () => {
    it.todo('returns a JSON-compatible representation of the node');
  });

  describe('BIP44Node.derive', () => {
    it.todo('derives a child node');
  });

  describe('deriveChildNode', () => {
    it.todo('derives a child node');
  });
});

describe('derivation', () => {
  it('initializes a BIP44Node', () => {
    const mnemonic =
      'romance hurry grit huge rifle ordinary loud toss sound congress upset twist';

    const bip39Node = `bip39:${mnemonic}` as const;

    // ethereum coin type
    const node = new BIP44Node({
      depth: 2,
      derivationPath: [bip39Node, `bip32:44'`, `bip32:60'`],
    });

    expect(node.key).toHaveLength(88);
    expect(node.depth).toStrictEqual(2);
    expect(node.toJSON()).toStrictEqual({
      depth: 2,
      key: expect.any(String),
    });
    console.log(node.toJSON());

    const ethereumAddressDeriver = getBIP44AddressKeyDeriver(node as any, {
      account: 0,
      change: 0,
    });
    console.log('Deriver path:', ethereumAddressDeriver.path);

    const account0Key = ethereumAddressDeriver(0);
    console.log(account0Key);
    expect(
      privateKeyToEthAddress(base64StringToBuffer(account0Key)).toString('hex'),
    ).toStrictEqual('5df603999c3d5ca2ab828339a9883585b1bce11b');

    expect(() => {
      node.derive([`bip32:60'`, `bip32:0'`, `bip32:0`, `bip32:0`]);
    }).toThrow(
      `Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "6"`,
    );

    // const childNode = node.derive([`bip32:44'`])
    // expect(childNode.key.length).toStrictEqual(88);
    // expect(childNode.depth).toStrictEqual(1);
  });

  // https://github.com/brave/eth-hd-keyring/blob/482acf341f01a8d1e924d55bfdbd309444a78e46/test/index.js#L10-L12
  it('eth-hd-keyring', () => {
    const sampleMnemonic =
      'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango';
    const firstAcct = '1c96099350f13d558464ec79b9be4445aa0ef579';
    const secondAcct = '1b00aed43a693f3a957f9feb5cc08afa031e37a0';

    const newBip39 = `bip39:${sampleMnemonic}` as const;

    // ethereum coin typ
    const node = new BIP44Node({
      depth: 2,
      derivationPath: [newBip39, `bip32:44'`, `bip32:60'`],
    });

    expect(node.key).toHaveLength(88);
    expect(node.depth).toStrictEqual(2);
    expect(node.toJSON()).toStrictEqual({
      depth: 2,
      key: expect.any(String),
    });
    console.log(node.toJSON());

    const ethereumAddressDeriver = getBIP44AddressKeyDeriver(node as any, {
      account: 0,
      change: 0,
    });
    console.log('Deriver path:', ethereumAddressDeriver.path);

    const account0Key = ethereumAddressDeriver(0);
    const account1Key = ethereumAddressDeriver(1);
    console.log(account0Key);
    expect(
      privateKeyToEthAddress(base64StringToBuffer(account0Key)).toString('hex'),
    ).toStrictEqual(firstAcct);

    expect(
      privateKeyToEthAddress(base64StringToBuffer(account1Key)).toString('hex'),
    ).toStrictEqual(secondAcct);

    expect(() => {
      node.derive([`bip32:60'`, `bip32:0'`, `bip32:0`, `bip32:0`]);
    }).toThrow(
      `Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "6"`,
    );

    // const childNode = node.derive([`bip32:44'`])
    // expect(childNode.key.length).toStrictEqual(88);
    // expect(childNode.depth).toStrictEqual(1);
  });

  // https://github.com/ethereumjs/ethereumjs-wallet/blob/master/test/hdkey.spec.ts
  it('ethereumjs-wallet', () => {
    const fixtureseed = Buffer.from(
      '747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03',
      'hex',
    );
    const seedKey = crypto
      .createHmac('sha512', Buffer.from('Bitcoin seed', 'utf8'))
      .update(fixtureseed)
      .digest();

    const fixturehd = hdkey.fromMasterSeed(fixtureseed);
    const childfixturehd = fixturehd.derivePath("m/44'/0'/0/1");
    const fixtureKey = childfixturehd.getWallet().getPrivateKey();

    // ethereum coin typ
    const _node = new BIP44Node({
      depth: 0,
      key: seedKey,
    });

    // const node = _node.derive([`bip32:44'`, `bip32:60'`])
    const node = _node.derive([`bip32:44'`, `bip32:0'`, `bip32:0`, `bip32:1`]);

    expect(node.key).toHaveLength(88);
    expect(node.depth).toStrictEqual(4);
    expect(node.toJSON()).toStrictEqual({
      depth: 4,
      key: expect.any(String),
    });
    console.log(node.toJSON());

    const account0Key = node.key;

    // const ethereumAddressDeriver = getBIP44AddressKeyDeriver(node as any, {
    //   account: 0,
    //   change: 0,
    // })
    // console.log('Deriver path:', ethereumAddressDeriver.path)

    // const account0Key = ethereumAddressDeriver(0)
    console.log(account0Key);
    // expect(account0Key).toStrictEqual(fixtureKey)
    expect(
      privateKeyToEthAddress(base64StringToBuffer(account0Key)).toString('hex'),
    ).toStrictEqual(childfixturehd.getWallet().getAddressString().slice(2));

    expect(node.keyBuffer.slice(0, 32).toString('base64')).toStrictEqual(
      fixtureKey.toString('base64'),
    );
    // console.log(fixtureKey)
    // console.log(node.keyAsBuffer.slice(32))

    // expect(() => {
    //   node.derive([`bip32:60'`, `bip32:0'`, `bip32:0`, `bip32:0`])
    // }).toThrow(`Invalid HD tree path depth: The depth must be a positive integer N such that 0 <= N <= 5. Received: "6"`)

    // const childNode = node.derive([`bip32:44'`])
    // expect(childNode.key.length).toStrictEqual(88);
    // expect(childNode.depth).toStrictEqual(1);
  });
});
