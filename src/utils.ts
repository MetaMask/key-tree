export function stripHexPrefix(hexString: string): string {
  return hexString.replace(/^0x/iu, '');
}

export function isValidHexString(hexString: string): boolean {
  return /^(?:0x)?[a-f0-9]+$/iu.test(hexString);
}

export function base64StringToBuffer(base64String: string) {
  return Buffer.from(base64String, 'base64');
}

export function hexStringToBuffer(hexString: string) {
  return Buffer.from(stripHexPrefix(hexString), 'hex');
}

export function bufferToBase64String(input: Buffer) {
  return input.toString('base64');
}
