const {generatePassword, calcStrength, buildPool} = require('../src/pwlib');

test('buildPool basic', ()=>{
  expect(buildPool({lower:true,upper:false,numbers:false,symbols:false,excludeAmbig:false}).length).toBeGreaterThan(0);
});

test('generate password length', ()=>{
  const pw = generatePassword(12, {lower:true,upper:true,numbers:true,symbols:false,excludeAmbig:true}, ()=>0);
  expect(pw.length).toBe(12);
});

test('strength calc', ()=>{
  expect(calcStrength('aB3$5678')).toBeGreaterThan(0);
});
