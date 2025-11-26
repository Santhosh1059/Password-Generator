// Small portable library for password generation and crypto helpers (Node + browser compatible where possible)
const {encryptPayload, decryptPayload, deriveKey} = require('./pwcrypto');

const AMBIG = "il1Lo0O";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMS = "0123456789";
const SYMS = "!@#$%^&*()-_=+[]{};:,.<>?/\\|~`";

function buildPool(options){
  let pool = '';
  if(options.lower) pool += LOWER;
  if(options.upper) pool += UPPER;
  if(options.numbers) pool += NUMS;
  if(options.symbols) pool += SYMS;
  if(options.excludeAmbig) pool = pool.split('').filter(c=>!AMBIG.includes(c)).join('');
  return pool;
}

function generatePassword(len, options, randFunc){
  const pool = buildPool(options);
  if(!pool.length) throw new Error('No charset selected');
  const r = randFunc || (n=>Math.floor(Math.random()*n));
  let pw = '';
  for(let i=0;i<len;i++) pw += pool[r(pool.length)];
  return pw;
}

function calcStrength(pw){
  let score = 0; if(pw.length>=8) score++; if(/[a-z]/.test(pw)) score++; if(/[A-Z]/.test(pw)) score++; if(/[0-9]/.test(pw)) score++; if(/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(100, Math.floor((score/5)*100));
}

module.exports = {buildPool, generatePassword, calcStrength, encryptPayload, decryptPayload, deriveKey};
