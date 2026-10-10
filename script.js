/**
 * Caesar Cipher Web Application
 * University of Balochistan — Information Security Programming, Assignment 1
 * Developed by Muhammad Ayan
 *
 * Sections:
 *   1. Core cipher functions
 *   2. Validation
 *   3. DOM references
 *   4. UI helpers  (shift strip, letter table, field errors, status)
 *   5. Event handlers
 *   6. Test suite
 */

(function () {
  'use strict';

  /* ==========================================================================
     SECTION 1: Core cipher functions (pure, no DOM access)
     ========================================================================== */

  /**
   * Encrypts an uppercase plaintext string using the Caesar cipher.
   * Formula: C[i] = (P[i] + k) mod 26
   *
   * @param {string} plaintext - Validated uppercase A-Z string.
   * @param {number} k - Shift key, integer in [0, 25].
   * @returns {string} Ciphertext.
   */
  function caesarEncrypt(plaintext, k) {
    let result = '';
    for (let i = 0; i < plaintext.length; i++) {
      const P = plaintext.charCodeAt(i) - 65;
      result += String.fromCharCode(((P + k) % 26) + 65);
    }
    return result;
  }

  /**
   * Decrypts an uppercase ciphertext string using the Caesar cipher.
   * Formula: P[i] = (C[i] - k + 26) mod 26
   *
   * The +26 guard prevents a negative remainder from JavaScript's % operator.
   * Example: (0 - 3 + 26) % 26 = 23 = 'X' — correct decryption of 'A' with k=3.
   *
   * @param {string} ciphertext - Validated uppercase A-Z string.
   * @param {number} k - Shift key, integer in [0, 25].
   * @returns {string} Plaintext.
   */
  function caesarDecrypt(ciphertext, k) {
    let result = '';
    for (let i = 0; i < ciphertext.length; i++) {
      const C = ciphertext.charCodeAt(i) - 65;
      result += String.fromCharCode(((C - k + 26) % 26) + 65);
    }
    return result;
  }

  /* ==========================================================================
     SECTION 2: Validation
     ========================================================================== */

  /**
   * Validates that text is non-empty and contains only uppercase A-Z.
   * @param {string} text
   * @returns {{ valid: boolean, error: string, value: string }}
   */
  function validateText(text) {
    if (text === '') {
      return { valid: false, error: 'Text is required.', value: text };
    }
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 65 || code > 90) {
        const ch  = text.charAt(i);
        const pos = i + 1;
        return {
          valid: false,
          error: "Invalid character '" + ch + "' at position " + pos + ". Only uppercase A-Z are allowed.",
          value: text
        };
      }
    }
    return { valid: true, error: '', value: text };
  }

  /**
   * Validates that the key is a whole integer string in [0, 25].
   * @param {string} keyString
   * @returns {{ valid: boolean, error: string, value: number|null }}
   */
  function validateKey(keyString) {
    if (keyString === '') {
      return { valid: false, error: 'Key is required.', value: null };
    }
    if (!/^\d+$/.test(keyString)) {
      return {
        valid: false,
        error: 'Key must be a whole number (no decimals, signs, or letters).',
        value: null
      };
    }
    const num = Number(keyString);
    if (num > 25) {
      return { valid: false, error: 'Key must be between 0 and 25.', value: null };
    }
    return { valid: true, error: '', value: num };
  }

  /* ==========================================================================
     SECTION 3: DOM references
     ========================================================================== */

  const textInput       = document.getElementById('text-input');
  const keyInput        = document.getElementById('key-input');
  const encryptBtn      = document.getElementById('encrypt-btn');
  const decryptBtn      = document.getElementById('decrypt-btn');
  const clearBtn        = document.getElementById('clear-btn');
  const resultOutput    = document.getElementById('result-output');
  const copyBtn         = document.getElementById('copy-btn');
  const swapBtn         = document.getElementById('swap-btn');
  const statusArea      = document.getElementById('status-area');
  const roundTripEl     = document.getElementById('round-trip-check');
  const runTestsBtn     = document.getElementById('run-tests-btn');
  const testSummaryEl   = document.getElementById('test-summary');
  const testTableBody   = document.getElementById('test-table-body');
  const autoUpperToggle = document.getElementById('auto-upper-toggle');
  const textErrorEl     = document.getElementById('text-error');
  const keyErrorEl      = document.getElementById('key-error');
  const stripPlainEl    = document.getElementById('strip-plain');
  const stripCipherEl   = document.getElementById('strip-cipher');
  const stripKeyDisplay = document.getElementById('strip-key-display');
  const ltLettersEl     = document.getElementById('lt-letters');
  const ltNumbersEl     = document.getElementById('lt-numbers');

  /* ==========================================================================
     SECTION 4: UI helpers
     ========================================================================== */

  /** Build the static A-Z → 0-25 letter table once on load. */
  function buildLetterTable() {
    for (let i = 0; i < 26; i++) {
      const letter = String.fromCharCode(65 + i);
      const lCell  = document.createElement('span');
      lCell.className = 'lt-cell';
      lCell.textContent = letter;
      ltLettersEl.appendChild(lCell);

      const nCell = document.createElement('span');
      nCell.className = 'lt-cell';
      nCell.textContent = String(i);
      ltNumbersEl.appendChild(nCell);
    }
  }

  /**
   * Rebuild the shift strip for a given key value.
   * @param {number} k - Integer in [0, 25].
   */
  function updateShiftStrip(k) {
    stripKeyDisplay.textContent = String(k);

    // Clear existing cells
    while (stripPlainEl.firstChild)  stripPlainEl.removeChild(stripPlainEl.firstChild);
    while (stripCipherEl.firstChild) stripCipherEl.removeChild(stripCipherEl.firstChild);

    for (let i = 0; i < 26; i++) {
      const plain  = String.fromCharCode(65 + i);
      const cipher = String.fromCharCode(((i + k) % 26) + 65);

      const pCell = document.createElement('span');
      pCell.className = 'shift-cell';
      pCell.textContent = plain;
      stripPlainEl.appendChild(pCell);

      const cCell = document.createElement('span');
      cCell.className = 'shift-cell';
      cCell.textContent = cipher;
      stripCipherEl.appendChild(cCell);
    }
  }

  /** Show or clear an inline field error element. */
  function setFieldError(el, message) {
    if (message) {
      el.textContent = message;
      el.classList.remove('hidden');
    } else {
      el.textContent = '';
      el.classList.add('hidden');
    }
  }

  /** Show a banner status message. */
  function showStatus(message, type) {
    statusArea.textContent = message;
    statusArea.className = 'status-area ' + type;
  }

  /** Clear the banner status message. */
  function clearStatus() {
    statusArea.textContent = '';
    statusArea.className = 'status-area';
  }

  /** Show round-trip verification result. */
  function showRoundTrip(passed) {
    roundTripEl.textContent = 'Round-trip check: ' + (passed ? 'PASS ✓' : 'FAIL ✗');
    roundTripEl.className = 'round-trip-check ' + (passed ? 'pass' : 'fail');
  }

  /** Clear result output, copy/swap buttons, and round-trip indicator. */
  function clearResultArea() {
    resultOutput.value = '';
    copyBtn.disabled = true;
    copyBtn.textContent = 'Copy';
    copyBtn.classList.remove('copied');
    swapBtn.disabled = true;
    roundTripEl.textContent = '';
    roundTripEl.className = 'round-trip-check';
  }

  /** Enable copy and swap after a result is produced. */
  function enableResultActions() {
    copyBtn.disabled = false;
    swapBtn.disabled = false;
  }

  /* ==========================================================================
     SECTION 5: Event handlers
     ========================================================================== */

  /** Shared validation + encrypt/decrypt runner. */
  function runCipher(mode) {
    const rawText = textInput.value;
    const rawKey  = keyInput.value;

    const textV = validateText(rawText);
    const keyV  = validateKey(rawKey);

    // Show inline field errors
    setFieldError(textErrorEl, textV.valid ? '' : textV.error);
    setFieldError(keyErrorEl,  keyV.valid  ? '' : keyV.error);

    if (!textV.valid || !keyV.valid) {
      clearResultArea();
      clearStatus();
      return;
    }

    const output = mode === 'encrypt'
      ? caesarEncrypt(textV.value, keyV.value)
      : caesarDecrypt(textV.value, keyV.value);

    resultOutput.value = output;
    enableResultActions();
    showStatus(mode === 'encrypt' ? 'Encryption successful.' : 'Decryption successful.', 'success');

    // Round-trip verification
    const verify = mode === 'encrypt'
      ? caesarDecrypt(output, keyV.value) === textV.value
      : caesarEncrypt(output, keyV.value) === textV.value;
    showRoundTrip(verify);
  }

  function handleEncrypt() { runCipher('encrypt'); }
  function handleDecrypt() { runCipher('decrypt'); }

  function handleClear() {
    textInput.value = '';
    keyInput.value  = '3';
    setFieldError(textErrorEl, '');
    setFieldError(keyErrorEl,  '');
    clearResultArea();
    clearStatus();
    updateShiftStrip(3);
    textInput.focus();
  }

  function handleInputKeydown(event) {
    if (event.key === 'Enter') {
      event.preventDefault();
      handleEncrypt();
    }
  }

  // Auto-uppercase: preserve cursor position
  textInput.addEventListener('input', function () {
    if (!autoUpperToggle.checked) return;
    const start = textInput.selectionStart;
    const end   = textInput.selectionEnd;
    textInput.value = textInput.value.toUpperCase();
    textInput.setSelectionRange(start, end);
  });

  // Update shift strip live as key changes
  keyInput.addEventListener('input', function () {
    const v = validateKey(keyInput.value);
    updateShiftStrip(v.valid ? v.value : 0);
  });

  // Copy to clipboard
  copyBtn.addEventListener('click', function () {
    if (!resultOutput.value) return;
    navigator.clipboard.writeText(resultOutput.value).then(function () {
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('copied');
      setTimeout(function () {
        copyBtn.textContent = 'Copy';
        copyBtn.classList.remove('copied');
      }, 2000);
    }).catch(function () {
      resultOutput.select();
      document.execCommand('copy');
    });
  });

  // Swap result → input
  swapBtn.addEventListener('click', function () {
    if (!resultOutput.value) return;
    textInput.value = resultOutput.value;
    clearResultArea();
    clearStatus();
    textInput.focus();
  });

  // Register main button listeners
  encryptBtn.addEventListener('click', handleEncrypt);
  decryptBtn.addEventListener('click', handleDecrypt);
  clearBtn.addEventListener('click', handleClear);
  textInput.addEventListener('keydown', handleInputKeydown);
  keyInput.addEventListener('keydown', handleInputKeydown);

  /* ==========================================================================
     SECTION 6: Test suite
     ========================================================================== */

  function runTestSuite() {
    const testCases = [
      {
        num: 1, name: 'Sample encrypt',
        input: 'ATTACKATDAWN', key: '3', expected: 'DWWDFNDWGDZQ',
        run: function () {
          const a = caesarEncrypt('ATTACKATDAWN', 3);
          return { actual: a, passed: a === 'DWWDFNDWGDZQ' };
        }
      },
      {
        num: 2, name: 'Sample decrypt',
        input: 'DWWDFNDWGDZQ', key: '3', expected: 'ATTACKATDAWN',
        run: function () {
          const a = caesarDecrypt('DWWDFNDWGDZQ', 3);
          return { actual: a, passed: a === 'ATTACKATDAWN' };
        }
      },
      {
        num: 3, name: 'k = 0 encrypt',
        input: 'HELLO', key: '0', expected: 'HELLO',
        run: function () {
          const a = caesarEncrypt('HELLO', 0);
          return { actual: a, passed: a === 'HELLO' };
        }
      },
      {
        num: 4, name: 'k = 0 decrypt',
        input: 'HELLO', key: '0', expected: 'HELLO',
        run: function () {
          const a = caesarDecrypt('HELLO', 0);
          return { actual: a, passed: a === 'HELLO' };
        }
      },
      {
        num: 5, name: 'k = 25 encrypt',
        input: 'ABC', key: '25', expected: 'ZAB',
        run: function () {
          const a = caesarEncrypt('ABC', 25);
          return { actual: a, passed: a === 'ZAB' };
        }
      },
      {
        num: 6, name: 'k = 25 decrypt',
        input: 'ZAB', key: '25', expected: 'ABC',
        run: function () {
          const a = caesarDecrypt('ZAB', 25);
          return { actual: a, passed: a === 'ABC' };
        }
      },
      {
        num: 7, name: 'Wrap-around encrypt',
        input: 'XYZ', key: '3', expected: 'ABC',
        run: function () {
          const a = caesarEncrypt('XYZ', 3);
          return { actual: a, passed: a === 'ABC' };
        }
      },
      {
        num: 8, name: 'Wrap-around decrypt (negative-modulo case)',
        input: 'ABC', key: '3', expected: 'XYZ',
        run: function () {
          const a = caesarDecrypt('ABC', 3);
          return { actual: a, passed: a === 'XYZ' };
        }
      },
      {
        num: 9, name: 'Round trip for ALL keys',
        input: 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG', key: '0–25', expected: '26/26 keys OK',
        run: function () {
          const s = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG';
          let ok = 0;
          for (let k = 0; k <= 25; k++) {
            if (caesarDecrypt(caesarEncrypt(s, k), k) === s) ok++;
          }
          const a = ok + '/26 keys OK';
          return { actual: a, passed: ok === 26 };
        }
      },
      {
        num: 10, name: 'Lowercase text',
        input: 'Hello', key: '3', expected: 'Rejected',
        run: function () { const r = validateText('Hello'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 11, name: 'Space in text',
        input: 'HELLO WORLD', key: '3', expected: 'Rejected',
        run: function () { const r = validateText('HELLO WORLD'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 12, name: 'Digits in text',
        input: 'ABC123', key: '3', expected: 'Rejected',
        run: function () { const r = validateText('ABC123'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 13, name: 'Punctuation in text',
        input: 'HELLO!', key: '3', expected: 'Rejected',
        run: function () { const r = validateText('HELLO!'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 14, name: 'Empty text',
        input: '""', key: '3', expected: 'Rejected',
        run: function () { const r = validateText(''); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 15, name: 'Key "-1"',
        input: 'HELLO', key: '-1', expected: 'Rejected',
        run: function () { const r = validateKey('-1'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 16, name: 'Key "26"',
        input: 'HELLO', key: '26', expected: 'Rejected',
        run: function () { const r = validateKey('26'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 17, name: 'Key "3.5"',
        input: 'HELLO', key: '3.5', expected: 'Rejected',
        run: function () { const r = validateKey('3.5'); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 18, name: 'Key "" (empty)',
        input: 'HELLO', key: '""', expected: 'Rejected',
        run: function () { const r = validateKey(''); return { actual: r.error, passed: !r.valid }; }
      },
      {
        num: 19, name: 'Key "abc"',
        input: 'HELLO', key: 'abc', expected: 'Rejected',
        run: function () { const r = validateKey('abc'); return { actual: r.error, passed: !r.valid }; }
      }
    ];

    let passedCount = 0;

    // Clear previous rows
    while (testTableBody.firstChild) {
      testTableBody.removeChild(testTableBody.firstChild);
    }

    testCases.forEach(function (tc) {
      const outcome = tc.run();
      if (outcome.passed) passedCount++;

      const row = document.createElement('tr');

      function addCell(text, extraClass) {
        const td = document.createElement('td');
        td.textContent = text;
        if (extraClass) td.className = extraClass;
        row.appendChild(td);
      }

      addCell(String(tc.num));
      addCell(tc.name);
      addCell(tc.input);
      addCell(tc.key);
      addCell(tc.expected);
      addCell(outcome.actual);
      addCell(outcome.passed ? 'PASS' : 'FAIL', outcome.passed ? 'result-pass' : 'result-fail');

      testTableBody.appendChild(row);
    });

    const total = testCases.length;
    testSummaryEl.textContent = passedCount + '/' + total + ' tests passed';
    testSummaryEl.className = 'test-summary ' + (passedCount === total ? 'pass' : 'fail');
  }

  runTestsBtn.addEventListener('click', runTestSuite);

  /* ==========================================================================
     Initialise on load
     ========================================================================== */
  buildLetterTable();
  updateShiftStrip(3);

})();
