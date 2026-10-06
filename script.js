/* ============================================================
   PassGuard — Password Strength Analyzer
   script.js
   ============================================================ */

// ── DATA ──────────────────────────────────────────────────────
const COMMON = new Set([
  'password','123456','qwerty','abc123','letmein','monkey',
  '1234567890','password1','iloveyou','admin','welcome','login',
  'passw0rd','master','hello','dragon','sunshine','princess',
  'shadow','football','baseball','superman','batman','trustno1',
  'access','password123','pass','test','guest','user','default',
  'secret','root','changeme','1q2w3e','qwertyuiop','111111',
  '123123','000000','mustang','michael','jessica','ashley',
  'bailey','zaq1zaq1','qazwsx'
]);

const WORDS = [
  'correct','horse','battery','staple','orange','market','dinner',
  'forest','purple','window','silver','golden','rocket','planet',
  'candle','castle','flying','mirror','bridge','island','winter',
  'summer','autumn','spring','yellow','coffee','garden','bottle',
  'finger','frozen','sunset','dragon','carpet','lemon','marble',
  'violet','anchor','breeze','copper','fossil'
];

// ── UTILITIES ─────────────────────────────────────────────────
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function calcEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  return pool > 0 ? Math.round(pw.length * Math.log2(pool)) : 0;
}

function crackTime(bits) {
  const seconds = Math.pow(2, bits) / 1e10;
  if (seconds < 1)         return '< 1 second';
  if (seconds < 60)        return Math.round(seconds) + ' seconds';
  if (seconds < 3600)      return Math.round(seconds / 60) + ' minutes';
  if (seconds < 86400)     return Math.round(seconds / 3600) + ' hours';
  if (seconds < 2592000)   return Math.round(seconds / 86400) + ' days';
  if (seconds < 31536000)  return Math.round(seconds / 2592000) + ' months';
  if (seconds < 1e9)       return Math.round(seconds / 31536000) + ' years';
  if (seconds < 1e12)      return 'centuries';
  return 'practically forever';
}

function checkIcon(pass) {
  if (pass) {
    return `<div class="check-icon pass">
      <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
    </div>`;
  }
  return `<div class="check-icon fail">
    <svg viewBox="0 0 24 24">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  </div>`;
}

// ── CORE ANALYSER ─────────────────────────────────────────────
function analyse() {
  const pw = document.getElementById('pwInput').value;
  if (!pw) { reset(); return; }

  // Character counts
  const len   = pw.length;
  const upC   = (pw.match(/[A-Z]/g) || []).length;
  const numC  = (pw.match(/[0-9]/g) || []).length;
  const symC  = (pw.match(/[^a-zA-Z0-9]/g) || []).length;

  // Boolean checks
  const hasUpper   = upC > 0;
  const hasLower   = /[a-z]/.test(pw);
  const hasNum     = numC > 0;
  const hasSym     = symC > 0;
  const isCommon   = COMMON.has(pw.toLowerCase());

  // Repeat check — only penalise if a single char repeats 4+ times in a row
  // OR if more than 40% of the password is made of 3+-run repeats (catches "aaa111bbb")
  const hasHardRepeat = /(.)\1{3,}/.test(pw); // e.g. "aaaa", "5555"
  const repeatMatches = pw.match(/(.)\1{2,}/g) || [];
  const repeatChars   = repeatMatches.reduce((sum, m) => sum + m.length, 0);
  const hasRepeat     = hasHardRepeat || (repeatChars / len > 0.4);

  // Sequence check — only penalise short passwords (< 14 chars) where the sequence
  // dominates, or passwords where sequences make up > 35% of total length.
  // This prevents "ghhrr3455#rtt233566555" (long, diverse) from being penalised
  // just because "345" or "566" appear inside a long digit string.
  const SEQ_RE = /(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)/gi;
  const seqMatches  = pw.match(SEQ_RE) || [];
  const seqChars    = seqMatches.reduce((sum, m) => sum + m.length, 0);
  // Penalise only if sequences are dominant relative to password length
  const hasSeq      = seqChars > 0 && (seqChars / len > 0.35 || (len < 14 && seqMatches.length >= 2));

  // ── STATS ──
  document.getElementById('sLen').textContent = len;
  document.getElementById('sUp').textContent  = upC;
  document.getElementById('sNum').textContent = numC;
  document.getElementById('sSym').textContent = symC;

  // ── SCORE ──
  let score = 0;
  if (len >= 8)   score++;
  if (len >= 12)  score++;
  if (len >= 16)  score++;
  if (len >= 20)  score++;          // bonus for very long passwords
  if (hasUpper)   score++;
  if (hasLower)   score++;
  if (hasNum)     score++;
  if (hasSym)     score++;
  if (numC >= 2)  score++;
  if (symC >= 2)  score++;

  // Penalties — applied after positive scoring
  if (isCommon)   score = Math.min(score, 1);
  // Soft penalties — never drag a long password below a fair floor
  const minFloor = len >= 16 ? 4 : (len >= 12 ? 2 : 0);
  if (hasRepeat)  score = Math.max(minFloor, score - 1);
  if (hasSeq)     score = Math.max(minFloor, score - 1);

  const pct = Math.min(100, Math.round((score / 10) * 100));

  // ── COLOUR / LABEL ──
  let color, label, badgeBg, badgeBorder;
  if (pct <= 20) {
    color = 'var(--red)'; label = 'Very weak';
    badgeBg = 'rgba(252,129,129,0.08)'; badgeBorder = 'rgba(252,129,129,0.2)';
  } else if (pct <= 40) {
    color = 'var(--orange)'; label = 'Weak';
    badgeBg = 'rgba(246,173,85,0.08)'; badgeBorder = 'rgba(246,173,85,0.2)';
  } else if (pct <= 60) {
    color = 'var(--yellow)'; label = 'Fair';
    badgeBg = 'rgba(246,224,94,0.08)'; badgeBorder = 'rgba(246,224,94,0.2)';
  } else if (pct <= 80) {
    color = 'var(--green)'; label = 'Strong';
    badgeBg = 'rgba(104,211,145,0.08)'; badgeBorder = 'rgba(104,211,145,0.2)';
  } else {
    color = 'var(--accent2)'; label = 'Very strong';
    badgeBg = 'rgba(99,179,237,0.1)'; badgeBorder = 'rgba(99,179,237,0.25)';
  }

  // Meter
  const fill = document.getElementById('meterFill');
  fill.style.width      = pct + '%';
  fill.style.background = color;

  // Score label
  const scoreEl = document.getElementById('scoreLabel');
  scoreEl.textContent  = label;
  scoreEl.style.color  = color;

  // Header badge
  const badge = document.getElementById('strengthBadge');
  badge.textContent = label;
  badge.style.color        = color;
  badge.style.background   = badgeBg;
  badge.style.borderColor  = badgeBorder;

  // ── CHECKS ──
  const checks = [
    { ok: len >= 8,       text: 'At least 8 characters' },
    { ok: len >= 12,      text: 'At least 12 characters' },
    { ok: len >= 16,      text: '16+ characters (excellent length)' },
    { ok: len >= 20,      text: '20+ characters (maximum length bonus)' },
    { ok: hasUpper,       text: 'Contains uppercase letters' },
    { ok: hasLower,       text: 'Contains lowercase letters' },
    { ok: hasNum,         text: 'Contains numbers' },
    { ok: hasSym,         text: 'Contains special characters' },
    { ok: !isCommon,      text: 'Not a common password' },
    { ok: !hasRepeat,     text: 'No excessive repeated characters (e.g. aaaa, 5555)' },
    { ok: !hasSeq,        text: 'No dominant sequential patterns (e.g. abc, 123)' },
  ];

  document.getElementById('checksContainer').innerHTML = checks.map(c => `
    <div class="check-item">
      ${checkIcon(c.ok)}
      <span class="check-text ${c.ok ? 'pass' : 'fail'}">${c.text}</span>
    </div>
  `).join('');

  // ── SUGGESTIONS ──
  const sugs = [];
  if (!hasUpper)            sugs.push('Add uppercase letters (A–Z) to increase character pool');
  if (!hasSym)              sugs.push('Include symbols like !, @, #, $ — they drastically increase entropy');
  if (len < 12)             sugs.push('Aim for 12+ characters — length is the strongest defence');
  if (len < 16 && pct > 50) sugs.push('Push past 16 characters for maximum protection');
  if (isCommon)             sugs.push('This password is in known breach lists — change it immediately');
  if (hasRepeat)            sugs.push('Avoid 4+ identical characters in a row (e.g. "aaaa", "5555")');
  if (hasSeq)               sugs.push('Reduce sequential patterns that dominate the password (e.g. "123123", "abcabc")');
  if (numC < 2)             sugs.push('Use two or more numbers spread across the password');
  if (pct >= 80)            sugs.push('Excellent! Store it in a password manager to keep it safe.');

  document.getElementById('sugContainer').innerHTML = sugs.length
    ? sugs.map(s => `
        <div class="suggestion-item">
          <div class="sug-dot"></div>
          <span>${s}</span>
        </div>`).join('')
    : '<div class="empty-state">No suggestions — looking good!</div>';

  // ── ENTROPY ──
  const bits = calcEntropy(pw);
  document.getElementById('entropyVal').textContent = bits + ' bits';
  document.getElementById('crackVal').textContent   = crackTime(bits);
  document.getElementById('entropyRow').style.opacity = '1';
}

// ── RESET ─────────────────────────────────────────────────────
function reset() {
  document.getElementById('meterFill').style.width = '0%';

  const scoreEl = document.getElementById('scoreLabel');
  scoreEl.textContent = '—';
  scoreEl.style.color = 'var(--text3)';

  const badge = document.getElementById('strengthBadge');
  badge.textContent            = '— awaiting input';
  badge.style.color            = 'var(--text3)';
  badge.style.background       = 'rgba(255,255,255,0.04)';
  badge.style.borderColor      = 'rgba(255,255,255,0.08)';

  ['sLen', 'sUp', 'sNum', 'sSym'].forEach(id => {
    document.getElementById(id).textContent = '0';
  });

  document.getElementById('checksContainer').innerHTML =
    '<div class="empty-state">No password entered yet</div>';
  document.getElementById('sugContainer').innerHTML =
    '<div class="empty-state">Suggestions appear here</div>';

  document.getElementById('entropyRow').style.opacity = '0.3';
  document.getElementById('entropyVal').textContent   = '—';
  document.getElementById('crackVal').textContent     = '—';
}

// ── TOGGLE VISIBILITY ─────────────────────────────────────────
function toggleVis() {
  const inp  = document.getElementById('pwInput');
  const icon = document.getElementById('eyeIcon');

  if (inp.type === 'password') {
    inp.type = 'text';
    icon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
      <line x1="1" y1="1" x2="23" y2="23"/>`;
  } else {
    inp.type = 'password';
    icon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>`;
  }
}

// ── PASSPHRASE GENERATOR ──────────────────────────────────────
function generatePassphrase() {
  const words = shuffle(WORDS).slice(0, 4);
  const num   = Math.floor(Math.random() * 90) + 10;
  const pw    = words
    .map((w, i) => i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w)
    .join('-') + num;

  const input = document.getElementById('pwInput');
  input.value = pw;
  input.type  = 'text';

  document.getElementById('eyeIcon').innerHTML = `
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
    <line x1="1" y1="1" x2="23" y2="23"/>`;

  analyse();
}