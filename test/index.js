const test = require('tape');

const {
  deriveKeyFromPath,
} = require('../src');
const {
  bip32: {
    deriveChildKey: bip32Derive,
    bip32PathToMultipath,
    privateKeyToEthAddress,
  },
  bip39: {
    deriveChildKey: bip39Derive,
    bip39MnemonicToMultipath,
  },
} = require('../src/derivers');

const defaultEthereumPath = `m/44'/60'/0'/0`;
const mnemonic = 'romance hurry grit huge rifle ordinary loud toss sound congress upset twist';
const expectedAddresses = [
  '5df603999c3d5ca2ab828339a9883585b1bce11b',
  '441c07e32a609afd319ffbb66432b424058bcfe9',
  '1f7c93dfe849c06dd610e77473bfaaef7f183c7c',
  '9e28bae18e0e358b12796697c6546f77d4657527',
  '6e7734c7f4fb973a3800b72fb1a6bf82d85d3d29',
  'f87328a8ea5208946c60dbd9385d4c8533ad5dd8',
  'bdc59c95b5afd6cb0318a24fd390f143fec85d51',
  '05751e88f2d9f0fccffc8d9c5188adaa378d60e4',
  'c4311bfd3fea0238a3f5ced088bd366b33f1e292',
  '7b99c781cbfff075229314ccbdc7f6d9e8440ad9',
];

test('ethereum key test - full path', (t) => {
  // generate keys
  const keys = expectedAddresses.map((_, index) => {
    const bip32Part = bip32PathToMultipath(`${defaultEthereumPath}/${index}`);
    const bip39Part = bip39MnemonicToMultipath(mnemonic);
    const multipath = `${bip39Part}/${bip32Part}`;
    t.equal(multipath, `bip39:${mnemonic}/bip32:44'/bip32:60'/bip32:0'/bip32:0/bip32:${index}`, 'matches expected multipath');
    return deriveKeyFromPath(multipath);
  });
  // validate addresses
  keys.forEach((key, index) => {
    const address = privateKeyToEthAddress(key);
    t.equal(address.toString('hex'), expectedAddresses[index]);
  });

  t.end();
});

test('ethereum key test - parent key reuse', (t) => {
  // generate parent key
  const bip32Part = bip32PathToMultipath(`${defaultEthereumPath}`);
  const bip39Part = bip39MnemonicToMultipath(mnemonic);
  const multipath = `${bip39Part}/${bip32Part}`;
  const parentKey = deriveKeyFromPath(multipath);
  const keys = expectedAddresses.map((_, index) => {
    return deriveKeyFromPath(`bip32:${index}`, parentKey);
  });

  // validate addresses
  keys.forEach((key, index) => {
    const address = privateKeyToEthAddress(key);
    t.equal(address.toString('hex'), expectedAddresses[index]);
  });

  t.end();
});

test('ethereum key test - direct derive', (t) => {
  // generate parent key
  let parentKey = null;
  parentKey = bip39Derive(parentKey, `romance hurry grit huge rifle ordinary loud toss sound congress upset twist`);
  parentKey = bip32Derive(parentKey, `44'`);
  parentKey = bip32Derive(parentKey, `60'`);
  parentKey = bip32Derive(parentKey, `0'`);
  parentKey = bip32Derive(parentKey, `0`);
  const keys = expectedAddresses.map((_, index) => {
    return bip32Derive(parentKey, `${index}`);
  });
  // validate addresses
  keys.forEach((key, index) => {
    const address = privateKeyToEthAddress(key);
    t.equal(address.toString('hex'), expectedAddresses[index]);
  });

  t.end();
});
