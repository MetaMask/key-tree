import {
  BASE_64_ENTROPY_LENGTH,
  BASE_64_REGEX,
  BASE_64_ZERO,
  KEY_BUFFER_LENGTH,
} from './constants';

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

export function isValidBufferEntropy(buffer: Buffer): boolean {
  if (buffer.length !== KEY_BUFFER_LENGTH) {
    return false;
  }

  for (const byte of buffer) {
    if (byte !== 0) {
      return true;
    }
  }
  return false;
}

function isValidBase64String(input: string) {
  return BASE_64_REGEX.test(input);
}

export function isValidHexStringEntropy(stringEntropy: string): boolean {
  if (!isValidHexString(stringEntropy)) {
    return false;
  }

  const stripped = stripHexPrefix(stringEntropy);
  if (stripped.length !== KEY_BUFFER_LENGTH) {
    return false;
  }

  if (/^0+$/iu.test(stripped)) {
    return false;
  }
  return true;
}

export function isValidBase64StringEntropy(stringEntropy: string): boolean {
  if (!isValidBase64String(stringEntropy)) {
    return false;
  }

  if (stringEntropy.length !== BASE_64_ENTROPY_LENGTH) {
    return false;
  }

  if (stringEntropy === BASE_64_ZERO) {
    return false;
  }
  return true;
}
