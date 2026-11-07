// Temporary API probe — run: node test/_probe.mjs  (delete after toolchain frozen)
import { x25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const xk = x25519.keygen();
console.log('x25519 keygen keys:', Object.keys(xk));

const wk = secp256k1.keygen();
console.log('secp256k1 keygen keys:', Object.keys(wk), 'pub type:', wk.publicKey?.constructor?.name);

const kem = ml_kem768.keygen();
console.log('kem keygen keys:', Object.keys(kem), 'pub len:', kem.secretKey !== undefined ? 'secretKey!' : kem.publicKey?.length, JSON.stringify(Object.fromEntries(Object.entries(kem).map(([k, v]) => [k, v?.length ?? v]))));
const enc = ml_kem768.encapsulate(kem.publicKey);
console.log('encapsulate:', JSON.stringify(Object.fromEntries(Object.entries(enc).map(([k, v]) => [k, v?.length ?? v]))));
const dec = ml_kem768.decapsulate(enc.cipherText, kem.secretKey);
console.log('kem ss match:', Buffer.compare(enc.sharedSecret, dec) === 0);

const dsa = ml_dsa65.keygen();
const msg = new TextEncoder().encode('attest');
const sig = ml_dsa65.sign(msg, dsa.secretKey);
console.log('dsa keygen keys:', Object.keys(dsa), 'pub len:', dsa.publicKey.length, 'sk len:', dsa.secretKey.length, 'sig len:', sig.length);
console.log('dsa verify:', ml_dsa65.verify(sig, msg, dsa.publicKey));

const shared = x25519.getSharedSecret(xk.secretKey, x25519.keygen().publicKey);
console.log('x25519 shared len:', shared.length);

const key = hkdf(sha256, shared, new Uint8Array(32), Buffer.from('probe'), 32);
console.log('hkdf key len:', key.length);

const nonce = randomBytes(24);
const aead = xchacha20poly1305(key, nonce, Buffer.from('aad'));
const ct = aead.encrypt(new TextEncoder().encode('hello'));
console.log('aead roundtrip:', Buffer.compare(aead.decrypt(ct), new TextEncoder().encode('hello')) === 0);
try { xchacha20poly1305(key, nonce, Buffer.from('bad')).decrypt(ct); console.log('tamper: NOT detected (bad)'); } catch { console.log('tamper: detected (good)'); }

console.log('hex utils:', bytesToHex(key).slice(0, 16), hexToBytes(bytesToHex(key)).length);
