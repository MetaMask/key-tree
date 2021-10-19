export default {
  // Fixtures defined and used in this package
  local: {
    mnemonic:
      'romance hurry grit huge rifle ordinary loud toss sound congress upset twist',
    addresses: [
      '5df603999c3d5ca2ab828339a9883585b1bce11b',
      '441c07e32a609afd319ffbb66432b424058bcfe9',
      '1f7c93dfe849c06dd610e77473bfaaef7f183c7c',
      '9e28bae18e0e358b12796697c6546f77d4657527',
      '6e7734c7f4fb973a3800b72fb1a6bf82d85d3d29',
      'f87328a8ea5208946c60dbd9385d4c8533ad5dd8',
    ],
  },

  // https://github.com/brave/eth-hd-keyring/blob/482acf341f01a8d1e924d55bfdbd309444a78e46/test/index.js#L10-L12
  // The state of the default branch as of 2021-10-19
  'eth-hd-keyring': {
    mnemonic:
      'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango',
    // "ethereumAddresses": [
    //   '1c96099350f13d558464ec79b9be4445aa0ef579',
    //   '1b00aed43a693f3a957f9feb5cc08afa031e37a0',
    // ]
  },

  // https://github.com/ethereumjs/ethereumjs-wallet/blob/2bc21b408da3b002a95aa752b94fa039ffc64e0f/test/hdkey.spec.ts
  // The state of the default branch as of 2021-10-19
  'ethereumjs-wallet': {
    seed: Buffer.from(
      '747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03',
      'hex',
    ),
    path: {
      ours: {
        tuple: [`bip32:44'`, `bip32:0'`, `bip32:0`, `bip32:1`],
        string: [`bip32:44'/bip32:0'/bip32:0/bip32:1`],
      },
      theirs: "m/44'/0'/0/1",
    },
    sampleIndices: [0, 1, 5, 50, 500, 5000],
  },
} as const;
