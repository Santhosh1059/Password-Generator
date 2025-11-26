// Password Generator with Notepad (localStorage)
(function(){
  const output = document.getElementById('passwordOutput');
  const tabNotes = document.getElementById('tabNotes');
  const tabHistory = document.getElementById('tabHistory');
  const lengthEl = document.getElementById('length');
  const lengthVal = document.getElementById('lengthVal');
  const lowerEl = document.getElementById('lowercase');
  const upperEl = document.getElementById('uppercase');
  const numbersEl = document.getElementById('numbers');
  const symbolsEl = document.getElementById('symbols');
  const excludeAmbigEl = document.getElementById('excludeAmbig');
  const regenBtn = document.getElementById('regenBtn');
  const copyBtn = document.getElementById('copyBtn');
  const strengthMeter = document.getElementById('strengthMeter').querySelector('span');
  const strengthText = document.getElementById('strengthText');
  const saveBtn = document.getElementById('saveBtn');
  const saveName = document.getElementById('saveName');
  const notesList = document.getElementById('notesList');
  const clearNotes = document.getElementById('clearNotes');
  const encryptToggle = document.getElementById('encryptToggle');
  const encPass = document.getElementById('encPass');
  const exportBtn = document.getElementById('exportBtn');
  const importFile = document.getElementById('importFile');
  const sessionPassInput = document.getElementById('sessionPass');
  const unlockBtn = document.getElementById('unlockBtn');
  const lockBtn = document.getElementById('lockBtn');
  const historyView = document.getElementById('historyView');
  const notesView = document.getElementById('notesView');
  const historyList = document.getElementById('historyList');
  const histFilter = document.getElementById('histFilter');
  const histMinLen = document.getElementById('histMinLen');
  const histMinStr = document.getElementById('histMinStr');

  const AMBIG = "il1Lo0O";
  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const NUMS = "0123456789";
  const SYMS = "!@#$%^&*()-_=+[]{};:,.<>?/\\|~`";

  function buildPool(){
    let pool = '';
    if(lowerEl.checked) pool += LOWER;
    if(upperEl.checked) pool += UPPER;
    if(numbersEl.checked) pool += NUMS;
    if(symbolsEl.checked) pool += SYMS;
    if(excludeAmbigEl.checked) pool = pool.split('').filter(c=>!AMBIG.includes(c)).join('');
    return pool;
  }

  function randInt(n){
    return Math.floor(Math.random()*n);
  }

  function secureRandomInt(n){
    // Use crypto API when available
    if(window.crypto && window.crypto.getRandomValues){
      const arr = new Uint32Array(1);
      window.crypto.getRandomValues(arr);
      return arr[0] % n;
    }
    return randInt(n);
  }

  function generate(){
    const len = Number(lengthEl.value);
    const pool = buildPool();
    if(!pool.length) { output.textContent = 'Select at least one charset'; return ''; }
    let pw = '';
    for(let i=0;i<len;i++){
      pw += pool[secureRandomInt(pool.length)];
    }
    output.textContent = pw;
    updateStrength(pw);
    return pw;
  }

  function updateStrength(pw){
    let score = 0;
    if(pw.length >= 8) score++;
    if(/[a-z]/.test(pw)) score++;
    if(/[A-Z]/.test(pw)) score++;
    if(/[0-9]/.test(pw)) score++;
    if(/[^A-Za-z0-9]/.test(pw)) score++;
    const pct = Math.min(100, Math.floor((score/5)*100));
    strengthMeter.style.width = pct + '%';
    if(pct < 40){ strengthText.textContent = 'Weak'; }
    else if(pct < 70){ strengthText.textContent = 'Okay'; }
    else { strengthText.textContent = 'Strong'; }
  }

  // --- Encryption helpers (Web Crypto, AES-GCM) ---
  // deriveKey(pass, saltUint8Array, iterations) -> CryptoKey
  async function deriveKey(pass, salt, iterations=120000){
    const enc = new TextEncoder();
    const saltArr = salt || crypto.getRandomValues(new Uint8Array(16));
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt: saltArr, iterations, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
  }

  // encryptJSON -> returns payload {version, alg, iterations, salt, iv, cipher}
  async function encryptJSON(obj, pass){
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pass, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data);
    return {
      version:1,
      alg:'AES-GCM',
      iterations:120000,
      salt: btoa(String.fromCharCode(...salt)),
      iv: btoa(String.fromCharCode(...iv)),
      cipher: btoa(String.fromCharCode(...new Uint8Array(ct)))
    };
  }

  // decryptJSON accepts either legacy combined base64 string, or payload object produced by encryptJSON
  async function decryptJSON(payload, pass){
    // legacy: string
    if(typeof payload === 'string'){
      const raw = Uint8Array.from(atob(payload), c=>c.charCodeAt(0));
      const iv = raw.slice(0,12); const ct = raw.slice(12);
      const key = await deriveKey(pass, null);
      const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
      return JSON.parse(new TextDecoder().decode(dec));
    }
    // payload object
    const salt = Uint8Array.from(atob(payload.salt), c=>c.charCodeAt(0));
    const iv = Uint8Array.from(atob(payload.iv), c=>c.charCodeAt(0));
    const ct = Uint8Array.from(atob(payload.cipher), c=>c.charCodeAt(0));
    const key = await deriveKey(pass, salt, payload.iterations || 120000);
    const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return JSON.parse(new TextDecoder().decode(dec));
  }

  function copyToClipboard(){
    const text = output.textContent;
    if(!text) return;
    navigator.clipboard.writeText(text).then(()=>{
      copyBtn.textContent = 'Copied!';
      setTimeout(()=>copyBtn.textContent='Copy',1200);
    }).catch(()=>{
      // fallback
      const tmp = document.createElement('textarea');
      tmp.value = text;document.body.appendChild(tmp);tmp.select();
      try{document.execCommand('copy');copyBtn.textContent='Copied!';setTimeout(()=>copyBtn.textContent='Copy',1200);}catch(e){alert('Copy failed');}
      tmp.remove();
    });
  }

  // --- Modal & Toast utilities ---
  const modalRoot = document.getElementById('modalRoot');
  const toastsRoot = document.getElementById('toasts');
  const persistEnc = document.getElementById('persistEnc');

  function showToast(msg, ms=2500){
    const el = document.createElement('div'); el.className='note';
    const span = document.createElement('span'); span.textContent = msg; const btn = document.createElement('button'); btn.textContent='✕'; btn.setAttribute('aria-label','Dismiss');
    btn.onclick = ()=>el.remove(); el.appendChild(span); el.appendChild(btn); toastsRoot.appendChild(el);
  if(ms>0) setTimeout(()=>{ try{ el.remove(); }catch(e){ console.warn('toast remove failed', e); } }, ms);
  }

  function showModal(title, message, buttons=[{id:'ok',label:'OK',value:true},{id:'cancel',label:'Cancel',value:false}]){
    return new Promise(resolve=>{
      // build modal
      modalRoot.innerHTML = '';
      modalRoot.setAttribute('aria-hidden','false'); modalRoot.setAttribute('role','dialog');
      const card = document.createElement('div'); card.className='card'; card.tabIndex = -1;
      const h = document.createElement('h3'); h.textContent = title; const p = document.createElement('p'); p.textContent = message;
      const actions = document.createElement('div'); actions.className='actions';
      const btnEls = [];
      for(const b of buttons){ const btn = document.createElement('button'); btn.textContent = b.label; btn.className='btn'; btn.dataset.value = JSON.stringify(b.value); btn.onclick=()=>{ close(b.value); }; actions.appendChild(btn); btnEls.push(btn); }
      card.appendChild(h); card.appendChild(p); card.appendChild(actions); modalRoot.appendChild(card);

      // focus trap
      const focusable = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
  // focusable buttons gathered dynamically below
      function onKey(e){
        if(e.key === 'Escape') { close(false); }
        if(e.key === 'Tab'){
          const focusables = Array.from(card.querySelectorAll(focusable)).filter(n=>!n.disabled);
          if(!focusables.length) return;
          const cur = document.activeElement; const idx = focusables.indexOf(cur);
          if(e.shiftKey){ if(idx===0){ e.preventDefault(); focusables[focusables.length-1].focus(); } }
          else { if(idx===focusables.length-1){ e.preventDefault(); focusables[0].focus(); } }
        }
      }

      // open
      setTimeout(()=>{ card.focus(); if(btnEls[0]) btnEls[0].focus(); document.addEventListener('keydown', onKey); }, 10);

      function close(val){ document.removeEventListener('keydown', onKey); modalRoot.setAttribute('aria-hidden','true'); modalRoot.innerHTML=''; resolve(val); }
    });
  }

  function saveNote(){
    const name = saveName.value.trim() || 'Untitled';
    const pw = output.textContent;
    if(!pw || pw.startsWith('Select')) return alert('Generate a password first');
    const notesPromise = Promise.resolve(loadNotes());
    notesPromise.then(async (notes)=>{
      const record = {id:Date.now(),name,pw};
      notes.unshift(record);
      addHistory(record);
      const sessionPass = sessionStorage.getItem('pw_session_pass');
      if(sessionPass){
        try{
          const payload = await encryptJSON(notes, sessionPass);
          localStorage.setItem('pw_notes_enc', JSON.stringify(payload));
          localStorage.removeItem('pw_notes');
        }catch(e){
          console.warn('Encryption save failed', e); localStorage.setItem('pw_notes', JSON.stringify(notes));
        }
      } else {
        localStorage.setItem('pw_notes', JSON.stringify(notes));
      }
      saveName.value = '';
      renderNotes();
    }).catch((e)=>{console.error(e)});
  }

  function loadNotes(){
    try{
      const encRaw = localStorage.getItem('pw_notes_enc');
      if(encRaw){
        const sessionPass = sessionStorage.getItem('pw_session_pass');
        if(!sessionPass) return [];
        const payload = JSON.parse(encRaw);
        // decryptJSON returns a Promise, so return that promise to caller
        return decryptJSON(payload, sessionPass);
      }
      const raw = localStorage.getItem('pw_notes');
      return raw?JSON.parse(raw):[];
    }catch(e){console.warn(e);return[]}
  }

  function renderNotes(){
    const res = loadNotes();
    // loadNotes can return Promise when encrypted storage is used
    Promise.resolve(res).then(notes=>{
      notesList.innerHTML = '';
      if(!notes || !notes.length) { notesList.innerHTML = '<li class="smallText">No saved passwords yet</li>'; return }
      for(const n of notes){
      const li = document.createElement('li'); li.className='note';
      const meta = document.createElement('div'); meta.className='meta';
      const title = document.createElement('div'); title.textContent = n.name; title.style.fontWeight='700';
      const sub = document.createElement('div'); sub.textContent = n.pw; sub.className='smallText';
      meta.appendChild(title); meta.appendChild(sub);
      const actions = document.createElement('div'); actions.className='actions';
      const copy = document.createElement('button'); copy.textContent='Copy'; copy.onclick=()=>{navigator.clipboard.writeText(n.pw)};
      const del = document.createElement('button'); del.textContent='Delete'; del.onclick=()=>{deleteNote(n.id)};
      actions.appendChild(copy); actions.appendChild(del);
      li.appendChild(meta); li.appendChild(actions);
      notesList.appendChild(li);
      }
    }).catch(()=>{ notesList.innerHTML = '<li class="smallText">No saved passwords yet</li>'; });
  }

  // --- History ---
  function addHistory(record){
    try{
      const h = JSON.parse(localStorage.getItem('pw_history')||'[]');
      h.unshift(Object.assign({ts:Date.now(), strength:calcStrength(record.pw)}, record));
      localStorage.setItem('pw_history', JSON.stringify(h.slice(0,500)));
      renderHistory();
    }catch(e){console.warn(e)}
  }

  function calcStrength(pw){
    let score = 0; if(pw.length>=8) score++; if(/[a-z]/.test(pw)) score++; if(/[A-Z]/.test(pw)) score++; if(/[0-9]/.test(pw)) score++; if(/[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(100, Math.floor((score/5)*100));
  }

  function loadHistory(){try{return JSON.parse(localStorage.getItem('pw_history')||'[]')}catch(e){return[]}}

  function renderHistory(){
    const h = loadHistory();
    const filter = histFilter.value.trim().toLowerCase();
    const minLen = Number(histMinLen.value)||0; const minStr = Number(histMinStr.value)||0;
    historyList.innerHTML = '';
    const filtered = h.filter(r=>{
      if(filter && !(r.name.toLowerCase().includes(filter) || r.pw.toLowerCase().includes(filter))) return false;
      if(minLen && r.pw.length < minLen) return false;
      if(minStr && r.strength < minStr) return false;
      return true;
    });
    if(!filtered.length) { historyList.innerHTML = '<li class="smallText">No history matches</li>'; return }
    for(const r of filtered){
      const li = document.createElement('li'); li.className='note';
      const meta = document.createElement('div'); meta.className='meta';
      const title = document.createElement('div'); title.textContent = `${r.name} — ${new Date(r.ts).toLocaleString()}`; title.style.fontWeight='700';
      const sub = document.createElement('div'); sub.textContent = `${r.pw} · ${r.strength}`; sub.className='smallText';
      meta.appendChild(title); meta.appendChild(sub);
      const actions = document.createElement('div'); actions.className='actions';
      const copy = document.createElement('button'); copy.textContent='Copy'; copy.onclick=()=>{navigator.clipboard.writeText(r.pw)};
      actions.appendChild(copy);
      li.appendChild(meta); li.appendChild(actions);
      historyList.appendChild(li);
    }
  }

  async function deleteNote(id){
    const ok = await showModal('Delete password', 'Are you sure you want to delete this saved password?', [{id:'del',label:'Delete',value:true},{id:'cancel',label:'Cancel',value:false}]);
    if(!ok) return;
    const notes = await Promise.resolve(loadNotes());
    const filtered = notes.filter(n=>n.id!==id);
    const sessionPass = sessionStorage.getItem('pw_session_pass');
    if(sessionPass){
      try{ const payload = await encryptJSON(filtered, sessionPass); localStorage.setItem('pw_notes_enc', JSON.stringify(payload)); localStorage.removeItem('pw_notes'); }
      catch(e){ localStorage.setItem('pw_notes', JSON.stringify(filtered)); }
    } else { localStorage.setItem('pw_notes', JSON.stringify(filtered)); }
    renderNotes(); showToast('Deleted');
  }

  async function clearAllNotes(){
    const ok = await showModal('Clear all', 'Clear all saved passwords and history? This action cannot be undone.', [{id:'clear',label:'Clear',value:true},{id:'cancel',label:'Cancel',value:false}]);
    if(!ok) return;
    localStorage.removeItem('pw_notes'); localStorage.removeItem('pw_notes_enc'); localStorage.removeItem('pw_history');
    renderNotes(); renderHistory(); showToast('All cleared');
  }

  // Export / Import
  exportBtn.addEventListener('click', async ()=>{
    const notes = await Promise.resolve(loadNotes());
    if(!notes || !notes.length) return alert('No notes to export');
    if(encryptToggle.checked){
      const pass = encPass.value; if(!pass) return alert('Enter passphrase');
      try{
        const payload = await encryptJSON(notes, pass);
        const wrapper = { exportedAt: new Date().toISOString(), encrypted:true, payload };
        const blob = new Blob([JSON.stringify(wrapper, null, 2)], {type:'application/json'});
        const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url; a.download='password-notes-encrypted.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      }catch(e){return alert('Encryption failed')}
    } else {
      const wrapper = { exportedAt: new Date().toISOString(), encrypted:false, notes };
      const blob = new Blob([JSON.stringify(wrapper, null, 2)], {type:'application/json'});
      const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url; a.download='password-notes.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    }
  });

  importFile.addEventListener('change', async (e)=>{
    const f = e.target.files && e.target.files[0]; if(!f) return; const txt = await f.text();
    try{
      const obj = JSON.parse(txt);
      // support wrapper from export
      if(obj && obj.encrypted && obj.payload){
        const pass = prompt('Enter passphrase to decrypt import'); if(!pass) return alert('Passphrase required');
        const data = await decryptJSON(obj.payload, pass);
        await handleImportMerge(data);
      } else if(obj && obj.notes){
        await handleImportMerge(obj.notes);
      } else if(Array.isArray(obj)){
        await handleImportMerge(obj);
      } else { throw new Error('Invalid format') }
      renderNotes(); alert('Import complete');
    }catch(err){console.error(err); alert('Import failed: '+err.message)}
    importFile.value='';
  });

  async function handleImportMerge(incoming){
    const existing = await Promise.resolve(loadNotes()) || [];
  const choice = await showModal('Import notes', 'Click Merge to merge imported notes with existing ones, or Replace to overwrite existing notes.', [{id:'merge',label:'Merge',value:true},{id:'replace',label:'Replace',value:false}]);
    let combined = [];
    if(choice){ // merge: append incoming before existing, dedupe by pw+name
      const map = new Map();
      for(const n of incoming.concat(existing)) map.set(n.name+"|"+n.pw, n);
      combined = Array.from(map.values());
    } else {
      combined = incoming.slice(0,500);
    }
    const sessionPass = sessionStorage.getItem('pw_session_pass');
    if(sessionPass){
      const payload = await encryptJSON(combined, sessionPass);
      localStorage.setItem('pw_notes_enc', JSON.stringify(payload)); localStorage.removeItem('pw_notes');
    } else {
      localStorage.setItem('pw_notes', JSON.stringify(combined.slice(0,500)));
    }
  }

  // Tabs and filters events
  tabNotes.addEventListener('click', ()=>{ notesView.hidden=false; historyView.hidden=true; tabNotes.setAttribute('aria-pressed','true'); tabHistory.setAttribute('aria-pressed','false'); });
  tabHistory.addEventListener('click', ()=>{ notesView.hidden=true; historyView.hidden=false; tabNotes.setAttribute('aria-pressed','false'); tabHistory.setAttribute('aria-pressed','true'); renderHistory(); });
  [histFilter, histMinLen, histMinStr].forEach(el=>el.addEventListener('input', renderHistory));

  // events
  lengthEl.addEventListener('input', ()=>{lengthVal.textContent = lengthEl.value; generate()});
  [lowerEl,upperEl,numbersEl,symbolsEl,excludeAmbigEl].forEach(el=>el.addEventListener('change', generate));
  regenBtn.addEventListener('click', generate);
  copyBtn.addEventListener('click', copyToClipboard);
  output.addEventListener('click', copyToClipboard);
  saveBtn.addEventListener('click', function(e){ e.preventDefault(); saveNote(); });
  clearNotes.addEventListener('click', clearAllNotes);

  // Session unlock/lock
  unlockBtn.addEventListener('click', async ()=>{
    const pass = sessionPassInput.value; if(!pass) return alert('Enter session passphrase');
    // try to decrypt existing encrypted notes if present
    const encRaw = localStorage.getItem('pw_notes_enc');
    if(encRaw){
      try{ const payload = JSON.parse(encRaw); await decryptJSON(payload, pass); }
      catch(e){ return alert('Unlock failed: wrong passphrase'); }
    }
    sessionStorage.setItem('pw_session_pass', pass);
    // if persistent encryption requested, store master payload under pw_notes_enc and remember pass in localStorage (user choice)
    if(persistEnc.checked){
      try{ const notes = await Promise.resolve(loadNotes()); const payload = await encryptJSON(notes, pass); localStorage.setItem('pw_notes_enc', JSON.stringify(payload)); localStorage.setItem('pw_master_pass_hash', btoa(pass)); }
      catch(e){ console.warn('persist encryption failed', e); }
    }
    unlockBtn.hidden = true; lockBtn.hidden = false; sessionPassInput.disabled = true;
    renderNotes(); renderHistory();
  });

  lockBtn.addEventListener('click', ()=>{
    sessionStorage.removeItem('pw_session_pass'); unlockBtn.hidden = false; lockBtn.hidden = true; sessionPassInput.disabled = false; sessionPassInput.value=''; renderNotes();
  });

  // keyboard shortcut: G to regenerate
  document.addEventListener('keydown', (e)=>{ if(e.key.toLowerCase()==='g') generate(); });

  // init
  function init(){ lengthVal.textContent = lengthEl.value; renderNotes(); generate(); }
  init();
})();
