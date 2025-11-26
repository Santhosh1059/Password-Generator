const {encryptPayload, decryptPayload} = require('../src/pwlib');

test('encrypt/decrypt payload', async ()=>{
  const sample = [{id:1,name:'test',pw:'Abc123!'}];
  const pass = 'unit-test-pass';
  const payload = await encryptPayload(sample, pass);
  expect(payload).toHaveProperty('salt');
  const dec = await decryptPayload(payload, pass);
  expect(Array.isArray(dec)).toBe(true);
  expect(dec[0].pw).toBe('Abc123!');
});
