// Crypto helpers usable in Node (with global crypto) and browser
const enc = new TextEncoder();
const dec = new TextDecoder();

async function deriveKey(pass, saltUint8, iterations=120000){
  const salt = saltUint8 || (typeof crypto !== 'undefined' && crypto.getRandomValues ? crypto.getRandomValues(new Uint8Array(16)) : Buffer.from('randomsalt'));
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}

async function encryptPayload(obj, pass){
  const salt = (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto.getRandomValues(new Uint8Array(16)) : Buffer.from('static-salt');
  const key = await deriveKey(pass, salt);
  const iv = (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto.getRandomValues(new Uint8Array(12)) : Buffer.from('static-iv-12');
  const data = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data);
  return {
    version:1,
    alg:'AES-GCM',
    iterations:120000,
    salt: Buffer.from(salt).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    cipher: Buffer.from(ct).toString('base64')
  };
}

async function decryptPayload(payload, pass){
  if(typeof payload === 'string'){
    // legacy base64 combined: not supported here
    throw new Error('Legacy format not supported in Node tests');
  }
  const salt = Buffer.from(payload.salt,'base64');
  const iv = Buffer.from(payload.iv,'base64');
  const ct = Buffer.from(payload.cipher,'base64');
  const key = await deriveKey(pass, new Uint8Array(salt), payload.iterations || 120000);
  const decbuf = await crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(iv)}, key, new Uint8Array(ct));
  return JSON.parse(dec.decode(decbuf));
}

module.exports = {deriveKey, encryptPayload, decryptPayload};
