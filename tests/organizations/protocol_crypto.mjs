// Independent client cryptography. Inputs/outputs stay in the private harness.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const input = JSON.parse(readFileSync(0, 'utf8'));
let result;
if (input.action === 'generate') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  result = { private: privateKey.export({ format: 'jwk' }), public: publicKey.export({ format: 'jwk' }) };
} else if (input.action === 'sign') {
  const key = createPrivateKey({ key: input.key, format: 'jwk' });
  result = { signature: sign(null, Buffer.from(input.data), key).toString('base64url') };
} else if (input.action === 'verify') {
  const [header, payload, signature] = input.token.split('.');
  const decoded = JSON.parse(Buffer.from(header, 'base64url'));
  if (!['RS256', 'EdDSA'].includes(decoded.alg)) throw new Error('Unexpected signing algorithm');
  const jwk = input.keys.find(key => key.kid === decoded.kid && key.alg === decoded.alg);
  if (!jwk) throw new Error('Signing key missing');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const valid = verify(decoded.alg === 'EdDSA' ? null : 'sha256', Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, 'base64url'));
  if (!valid) throw new Error('Invalid signature');
  result = { header: decoded, claims: JSON.parse(Buffer.from(payload, 'base64url')) };
} else {
  throw new Error('Unknown client cryptography action');
}
process.stdout.write(JSON.stringify(result));
