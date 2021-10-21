import * as mod from '.';

// This is purely for coverage shenanigans
describe('index', () => {
  it('has expected exports', () => {
    expect(mod.MAX_BIP_44_DEPTH).toStrictEqual(5);
  });
});
