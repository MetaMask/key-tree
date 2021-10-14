export function stripHexPrefix(hexString: string): string {
  return hexString.replace(/^0x/iu, '');
}

export function isValidHexString(hexString: string): boolean {
  return /^(?:0x)?[a-f0-9]+$/iu.test(hexString);
}

export function getHexBuffer(input: string | Buffer) {
  return Buffer.isBuffer(input)
    ? input
    : Buffer.from(stripHexPrefix(input), 'hex');
}

export function bufferToHexString(input: Buffer) {
  return input.toString('hex');
}
