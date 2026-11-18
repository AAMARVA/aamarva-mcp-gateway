import { sha256Hex } from '../config/security.ts';

const TOKEN_FORMAT_REGEX = /^agw1\.(tok_[0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/;

export interface ParsedToken {
  tokenId: string;
  tokenHash: string;
}

export function validateAndHashToken(plaintextToken: string): ParsedToken | null {
  if (typeof plaintextToken !== 'string') {
    return null;
  }
  const match = TOKEN_FORMAT_REGEX.exec(plaintextToken.trim());
  if (!match) {
    return null;
  }
  return {
    tokenId: match[1],
    tokenHash: sha256Hex(plaintextToken.trim()),
  };
}
