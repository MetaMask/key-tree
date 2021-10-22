import * as mod from '.';

// This is purely for coverage shenanigans
describe('index', () => {
  it('has expected exports', () => {
    const { MAX_BIP_44_DEPTH, PackageBuffer } = mod;

    expect(MAX_BIP_44_DEPTH).toStrictEqual(5);
    expect(PackageBuffer).toStrictEqual(Buffer);
  });
});
