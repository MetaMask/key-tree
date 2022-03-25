import * as mod from '.';

// This is purely for coverage shenanigans
describe('index', () => {
  it('has expected exports', () => {
    const { MAX_BIP_44_DEPTH, MIN_BIP_44_DEPTH, PackageBuffer, SLIP10Node, secp256k1, ed25519 } =
      mod;

    expect(MAX_BIP_44_DEPTH).toStrictEqual(5);
    expect(MIN_BIP_44_DEPTH).toStrictEqual(0);
    expect(PackageBuffer).toStrictEqual(Buffer);

    expect(SLIP10Node).toBeDefined();
    expect(secp256k1).toBeDefined();
    expect(ed25519).toBeDefined();
  });
});
