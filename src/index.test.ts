import {
  MAX_BIP_44_DEPTH,
  MIN_BIP_44_DEPTH,
  SLIP10Node,
  secp256k1,
  ed25519,
  isValidBIP32PathSegment,
  createBip39KeyFromSeed,
  mnemonicPhraseToBytes,
  ed25519Bip32,
  getBIP44CoinTypeToAddressPathTuple,
  mnemonicToSeed,
  hmacSha512,
  keccak256,
  pbkdf2Sha512,
  ripemd160,
  sha256,
  getPublicKeyForCurve,
} from '.';
import * as index from '.';
import * as guard from './guard';

// This is purely for coverage shenanigans
describe('index', () => {
  it('has expected exports', () => {
    expect(MAX_BIP_44_DEPTH).toBe(5);
    expect(MIN_BIP_44_DEPTH).toBe(0);

    expect(SLIP10Node).toBeDefined();
    expect(secp256k1).toBeDefined();
    expect(ed25519).toBeDefined();
    expect(ed25519Bip32).toBeDefined();
    expect(isValidBIP32PathSegment).toBeDefined();
    expect(createBip39KeyFromSeed).toBeDefined();
    expect(mnemonicPhraseToBytes).toBeDefined();
    expect(getBIP44CoinTypeToAddressPathTuple).toBeDefined();
    expect(mnemonicToSeed).toBeDefined();
    expect(hmacSha512).toBeDefined();
    expect(keccak256).toBeDefined();
    expect(pbkdf2Sha512).toBeDefined();
    expect(ripemd160).toBeDefined();
    expect(sha256).toBeDefined();
    expect(getPublicKeyForCurve).toBeDefined();
  });

  it.each(Object.keys(guard))('does not export %s', (property) => {
    expect(index).not.toHaveProperty(property);
  });
});
