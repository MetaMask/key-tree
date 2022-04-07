import { isValidBufferKey, nullableHexStringToBuffer } from './utils';

describe('nullableHexStringToBuffer', () => {
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
