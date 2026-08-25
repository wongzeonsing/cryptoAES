// ==UserScript==
// @name         AES 解密响应字段
// @namespace    http://tampermonkey.net/
// @version      2026.08.26
// @description  自动拦截并解密接口请求与返回值，支持 CBC/ECB 模式、IV、多规则及自定义字段路径，完全兼容油猴与 Stay
// @match        *://*/*
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @run-at       document-start
// @updateURL    https://raw.githubusercontent.com/wongzeonsing/cryptoAES/main/cryptoAES.user.js
// @downloadURL  https://raw.githubusercontent.com/wongzeonsing/cryptoAES/main/cryptoAES.user.js
// ==/UserScript==

(function() {
  'use strict';

  // 1. 存储层：GM_* 优先，localStorage 回退
  var storage = {
    get: function(k, d) {
      if (typeof GM_getValue !== 'undefined') {
        try { var val = GM_getValue(k); return (val !== undefined && val !== null) ? val : d; } catch(e) {}
      }
      try {
        var v = localStorage.getItem('aes_' + k);
        return v === null ? d : JSON.parse(v);
      } catch(e) {
        return d;
      }
    },
    set: function(k, v) {
      if (typeof GM_setValue !== 'undefined') {
        try { GM_setValue(k, v); return; } catch(e) {}
      }
      try {
        localStorage.setItem('aes_' + k, JSON.stringify(v));
      } catch(e) {}
    }
  };

  // 2. 读取并迁移规则数据
  function loadRules() {
    var rules = storage.get('rules', null);
    if (!rules || !Array.isArray(rules) || rules.length === 0) {
      // 检查旧版配置进行向下兼容迁移
      var legacyKeywords = storage.get('urlKeywords', '');
      var legacyKey = storage.get('aesKey', '');
      var legacyField = storage.get('aesField', '');
      if (legacyKeywords || legacyKey || legacyField) {
        rules = [{
          id: 'rule_' + Date.now(),
          name: '默认规则',
          urlKeywords: legacyKeywords || '',
          mode: 'ECB',
          key: legacyKey || '',
          iv: '',
          resField: legacyField || '',
          reqField: ''
        }];
        storage.set('rules', rules);
      } else {
        rules = [{
          id: 'rule_' + Date.now(),
          name: '默认规则',
          urlKeywords: '',
          mode: 'ECB',
          key: '',
          iv: '',
          resField: '',
          reqField: ''
        }];
      }
    }
    return rules;
  }

  var currentRules = loadRules();

  // 3. 页面主环境注入脚本 (包含精简 MiniCryptoJS，零网络依赖，免除 CSP 限制)
  function pageContextRunner(rulesJsonStr) {
    if (window.__aesHooksInstalled) {
      window.__aesRules = JSON.parse(rulesJsonStr);
      return;
    }
    window.__aesHooksInstalled = true;
    window.__aesRules = JSON.parse(rulesJsonStr);

    // --- 内嵌精简 CryptoJS 核心 ---
    var MiniCrypto = (function () {
      var C = {};
      var C_lib = C.lib = {};
      var Base = C_lib.Base = {
        extend: function (overrides) {
          var subtype = function () {};
          subtype.prototype = this;
          var instance = new subtype();
          if (overrides) instance.mixIn(overrides);
          if (!instance.hasOwnProperty('init')) {
            instance.init = function () { instance.$super.init.apply(this, arguments); };
          }
          instance.init.prototype = instance;
          instance.$super = this;
          return instance;
        },
        create: function () {
          var instance = this.extend();
          instance.init.apply(instance, arguments);
          return instance;
        },
        init: function () {},
        mixIn: function (properties) {
          for (var p in properties) if (properties.hasOwnProperty(p)) this[p] = properties[p];
          if (properties.hasOwnProperty('toString')) this.toString = properties.toString;
        },
        clone: function () { return this.init.prototype.extend(this); }
      };

      var WordArray = C_lib.WordArray = Base.extend({
        init: function (words, sigBytes) {
          words = this.words = words || [];
          this.sigBytes = sigBytes !== undefined ? sigBytes : words.length * 4;
        },
        toString: function (encoder) { return (encoder || C_enc.Hex).stringify(this); },
        concat: function (wordArray) {
          var thisWords = this.words, thatWords = wordArray.words;
          var thisSigBytes = this.sigBytes, thatSigBytes = wordArray.sigBytes;
          this.clamp();
          if (thisSigBytes % 4) {
            for (var i = 0; i < thatSigBytes; i++) {
              var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
              thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
            }
          } else {
            for (var i = 0; i < thatSigBytes; i += 4) thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
          }
          this.sigBytes += thatSigBytes;
          return this;
        },
        clamp: function () {
          var words = this.words, sigBytes = this.sigBytes;
          words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
          words.length = Math.ceil(sigBytes / 4);
        },
        clone: function () {
          var clone = Base.clone.call(this);
          clone.words = this.words.slice(0);
          return clone;
        }
      });

      var C_enc = C.enc = {};
      var Hex = C_enc.Hex = {
        stringify: function (wordArray) {
          var words = wordArray.words, sigBytes = wordArray.sigBytes;
          var hexChars = [];
          for (var i = 0; i < sigBytes; i++) {
            var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            hexChars.push((bite >>> 4).toString(16));
            hexChars.push((bite & 0x0f).toString(16));
          }
          return hexChars.join('');
        },
        parse: function (hexStr) {
          var hexStrLength = hexStr.length, words = [];
          for (var i = 0; i < hexStrLength; i += 2) {
            words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
          }
          return WordArray.create(words, hexStrLength / 2);
        }
      };

      var Latin1 = C_enc.Latin1 = {
        stringify: function (wordArray) {
          var words = wordArray.words, sigBytes = wordArray.sigBytes, latin1Chars = [];
          for (var i = 0; i < sigBytes; i++) {
            var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
          }
          return latin1Chars.join('');
        },
        parse: function (latin1Str) {
          var latin1StrLength = latin1Str.length, words = [];
          for (var i = 0; i < latin1StrLength; i++) {
            words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
          }
          return WordArray.create(words, latin1StrLength);
        }
      };

      var Utf8 = C_enc.Utf8 = {
        stringify: function (wordArray) {
          try { return decodeURIComponent(escape(Latin1.stringify(wordArray))); } catch (e) { return Latin1.stringify(wordArray); }
        },
        parse: function (utf8Str) { return Latin1.parse(unescape(encodeURIComponent(utf8Str))); }
      };

      var Base64 = C_enc.Base64 = {
        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
        stringify: function (wordArray) {
          var words = wordArray.words, sigBytes = wordArray.sigBytes, map = this._map;
          wordArray.clamp();
          var base64Chars = [];
          for (var i = 0; i < sigBytes; i += 3) {
            var byte1 = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
            var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;
            var triplet = (byte1 << 16) | (byte2 << 8) | byte3;
            for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
          }
          var paddingChar = map.charAt(64);
          if (paddingChar) while (base64Chars.length % 4) base64Chars.push(paddingChar);
          return base64Chars.join('');
        },
        parse: function (base64Str) {
          var base64StrLength = base64Str.length, map = this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            reverseMap = this._reverseMap = [];
            for (var j = 0; j < map.length; j++) reverseMap[map.charCodeAt(j)] = j;
          }
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            var paddingIndex = base64Str.indexOf(paddingChar);
            if (paddingIndex !== -1) base64StrLength = paddingIndex;
          }
          var words = [], nBytes = 0;
          for (var i = 0; i < base64StrLength; i++) {
            if (i % 4) {
              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
              words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
              nBytes++;
            }
          }
          return WordArray.create(words, nBytes);
        }
      };

      var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
        reset: function () { this._data = WordArray.create(); this._nDataBytes = 0; },
        _append: function (data) {
          if (typeof data == 'string') data = Utf8.parse(data);
          this._data.concat(data);
          this._nDataBytes += data.sigBytes;
        },
        _process: function (doFlush) {
          var data = this._data, dataWords = data.words, dataSigBytes = data.sigBytes;
          var blockSize = this.blockSize, blockSizeBytes = blockSize * 4;
          var nBlocksReady = dataSigBytes / blockSizeBytes;
          nBlocksReady = doFlush ? Math.ceil(nBlocksReady) : Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
          var nWordsReady = nBlocksReady * blockSize;
          var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);
          if (nWordsReady) {
            for (var offset = 0; offset < nWordsReady; offset += blockSize) this._doProcessBlock(dataWords, offset);
            var processedWords = dataWords.splice(0, nWordsReady);
            data.sigBytes -= nBytesReady;
          }
          return WordArray.create(processedWords, nBytesReady);
        },
        clone: function () { var clone = Base.clone.call(this); clone._data = this._data.clone(); return clone; },
        _minBufferSize: 0
      });

      var C_pad = C.pad = {};
      var Pkcs7 = C_pad.Pkcs7 = {
        pad: function (data, blockSize) {
          var blockSizeBytes = blockSize * 4;
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;
          var padByte = nPaddingBytes;
          var padWrapper = (padByte << 24) | (padByte << 16) | (padByte << 8) | padByte;
          var padWords = [];
          for (var i = 0; i < nPaddingBytes; i += 4) padWords.push(padWrapper);
          data.concat(WordArray.create(padWords, nPaddingBytes));
        },
        unpad: function (data) {
          var sigBytes = data.sigBytes;
          var nPaddingBytes = data.words[(sigBytes - 1) >>> 2] & 0xff;
          if (nPaddingBytes > 0 && nPaddingBytes <= (sigBytes % 4 || 4) + (data.words.length - 1) * 4) {
            data.sigBytes -= nPaddingBytes;
          }
        }
      };

      var C_mode = C.mode = {};
      var Mode = C_lib.BlockCipherMode = Base.extend({
        createEncryptor: function (cipher, iv) { return this.Encryptor.create(cipher, iv); },
        createDecryptor: function (cipher, iv) { return this.Decryptor.create(cipher, iv); },
        init: function (cipher, iv) { this._cipher = cipher; this._iv = iv; }
      });

      var CBC = C_mode.CBC = (function () {
        var CBC = Mode.extend();
        CBC.Encryptor = CBC.extend({
          processBlock: function (words, offset) {
            var cipher = this._cipher, blockSize = cipher.blockSize;
            xorBlock.call(this, words, offset, blockSize);
            cipher.encryptBlock(words, offset);
            this._prevBlock = words.slice(offset, offset + blockSize);
          }
        });
        CBC.Decryptor = CBC.extend({
          processBlock: function (words, offset) {
            var cipher = this._cipher, blockSize = cipher.blockSize;
            var thisBlock = words.slice(offset, offset + blockSize);
            cipher.decryptBlock(words, offset);
            xorBlock.call(this, words, offset, blockSize);
            this._prevBlock = thisBlock;
          }
        });
        function xorBlock(words, offset, blockSize) {
          var block = this._prevBlock || this._iv;
          if (block) {
            var blockWords = block.words || block;
            for (var i = 0; i < blockSize; i++) words[offset + i] ^= blockWords[i];
          }
          this._prevBlock = undefined;
        }
        return CBC;
      }());

      var ECB = C_mode.ECB = (function () {
        var ECB = Mode.extend();
        ECB.Encryptor = ECB.extend({
          processBlock: function (words, offset) { this._cipher.encryptBlock(words, offset); }
        });
        ECB.Decryptor = ECB.extend({
          processBlock: function (words, offset) { this._cipher.decryptBlock(words, offset); }
        });
        return ECB;
      }());

      var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
        cfg: Base.extend({ mode: CBC, padding: Pkcs7 }),
        createEncryptor: function (key, cfg) { return this.create(this._ENC_XFORM_MODE, key, cfg); },
        createDecryptor: function (key, cfg) { return this.create(this._DEC_XFORM_MODE, key, cfg); },
        init: function (xformMode, key, cfg) {
          this.cfg = this.cfg.extend(cfg);
          this._xformMode = xformMode;
          this._key = key;
          this.reset();
        },
        reset: function () { BufferedBlockAlgorithm.reset.call(this); this._doReset(); },
        process: function (dataUpdate) { this._append(dataUpdate); return this._process(); },
        finalize: function (dataUpdate) { if (dataUpdate) this._append(dataUpdate); return this._doFinalize(); },
        _ENC_XFORM_MODE: 1,
        _DEC_XFORM_MODE: 2
      });

      var BlockCipher = C_lib.BlockCipher = Cipher.extend({
        cfg: Cipher.cfg.extend({ mode: CBC, padding: Pkcs7 }),
        reset: function () {
          Cipher.reset.call(this);
          var cfg = this.cfg, iv = cfg.iv, mode = cfg.mode;
          if (this._xformMode == this._ENC_XFORM_MODE) {
            this._mode = mode.createEncryptor(this, iv && iv.words ? iv : iv);
          } else {
            this._mode = mode.createDecryptor(this, iv && iv.words ? iv : iv);
            this._minBufferSize = 1;
          }
        },
        _doProcessBlock: function (words, offset) { this._mode.processBlock(words, offset); },
        _doFinalize: function () {
          var padding = this.cfg.padding;
          if (this._xformMode == this._ENC_XFORM_MODE) {
            padding.pad(this._data, this.blockSize);
            return this._process(true);
          } else {
            var finalBlocks = this._process(true);
            padding.unpad(finalBlocks);
            return finalBlocks;
          }
        },
        blockSize: 128 / 32
      });

      var SBOX = [], INV_SBOX = [], SUB_MIX_0 = [], SUB_MIX_1 = [], SUB_MIX_2 = [], SUB_MIX_3 = [];
      var INV_SUB_MIX_0 = [], INV_SUB_MIX_1 = [], INV_SUB_MIX_2 = [], INV_SUB_MIX_3 = [];

      (function () {
        var d = [];
        for (var i = 0; i < 256; i++) d[i] = i < 128 ? i << 1 : (i << 1) ^ 0x11b;
        var x = 0, xi = 0;
        for (var i = 0; i < 256; i++) {
          var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
          sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
          SBOX[x] = sx; INV_SBOX[sx] = x;
          var x2 = d[x], x4 = d[x2], x8 = d[x4];
          var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
          SUB_MIX_0[x] = (t << 24) | (t >>> 8); SUB_MIX_1[x] = (t << 16) | (t >>> 16);
          SUB_MIX_2[x] = (t << 8) | (t >>> 24); SUB_MIX_3[x] = t;
          t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
          INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8); INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
          INV_SUB_MIX_2[sx] = (t << 8) | (t >>> 24); INV_SUB_MIX_3[sx] = t;
          if (!x) { x = xi = 1; } else { x = x2 ^ d[d[d[x8 ^ x2]]]; xi ^= d[d[xi]]; }
        }
      }());

      var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

      var AES = C_lib.AES = BlockCipher.extend({
        _doReset: function () {
          var key = this._key, keyWords = key.words, keySize = key.sigBytes / 4;
          var nRounds = this._nRounds = keySize + 6;
          var ksRows = (nRounds + 1) * 4, keySchedule = this._keySchedule = [];
          for (var ksRow = 0; ksRow < ksRows; ksRow++) {
            if (ksRow < keySize) {
              keySchedule[ksRow] = keyWords[ksRow];
            } else {
              var t = keySchedule[ksRow - 1];
              if (!(ksRow % keySize)) {
                t = (t << 8) | (t >>> 24);
                t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
                t ^= RCON[(ksRow / keySize) | 0] << 24;
              } else if (keySize > 6 && ksRow % keySize == 4) {
                t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
              }
              keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
            }
          }
          var invKeySchedule = this._invKeySchedule = [];
          for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
            var ksRow = ksRows - invKsRow;
            var t = (invKsRow % 4) ? keySchedule[ksRow] : keySchedule[ksRow - 4];
            if (invKsRow < 4 || ksRow <= 4) {
              invKeySchedule[invKsRow] = t;
            } else {
              invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^ INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
            }
          }
        },
        encryptBlock: function (M, offset) {
          this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
        },
        decryptBlock: function (M, offset) {
          var t = M[offset + 1]; M[offset + 1] = M[offset + 3]; M[offset + 3] = t;
          this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);
          t = M[offset + 1]; M[offset + 1] = M[offset + 3]; M[offset + 3] = t;
        },
        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
          var nRounds = this._nRounds;
          var s0 = M[offset] ^ keySchedule[0], s1 = M[offset + 1] ^ keySchedule[1];
          var s2 = M[offset + 2] ^ keySchedule[2], s3 = M[offset + 3] ^ keySchedule[3];
          var ksRow = 4;
          for (var round = 1; round < nRounds; round++) {
            var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
            var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
            var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
            var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
          }
          var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
          var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
          var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
          var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];
          M[offset] = t0; M[offset + 1] = t1; M[offset + 2] = t2; M[offset + 3] = t3;
        }
      });

      C.AES = {
        encrypt: function (message, key, cfg) {
          if (typeof message == 'string') message = Utf8.parse(message);
          if (typeof key == 'string') key = Utf8.parse(key);
          cfg = cfg || {};
          if (cfg.iv && typeof cfg.iv == 'string') cfg.iv = Utf8.parse(cfg.iv);
          var encryptor = AES.createEncryptor(key, cfg);
          var ciphertext = encryptor.finalize(message);
          return {
            ciphertext: ciphertext,
            key: key,
            iv: cfg.iv,
            toString: function (formatter) { return (formatter || Base64).stringify(this.ciphertext); }
          };
        },
        decrypt: function (ciphertext, key, cfg) {
          if (typeof ciphertext == 'string') {
            var cleanStr = ciphertext.replace(/[\r\n\s]/g, '');
            if (/^[0-9a-fA-F]+$/.test(cleanStr) && cleanStr.length % 2 === 0 && !cleanStr.includes('=') && cleanStr.length >= 32) {
              try { ciphertext = Hex.parse(cleanStr); } catch(e) { ciphertext = Base64.parse(cleanStr); }
            } else {
              ciphertext = Base64.parse(cleanStr);
            }
          } else if (ciphertext && ciphertext.ciphertext) {
            ciphertext = ciphertext.ciphertext;
          }
          if (typeof key == 'string') key = Utf8.parse(key);
          cfg = cfg || {};
          if (cfg.iv && typeof cfg.iv == 'string') cfg.iv = Utf8.parse(cfg.iv);
          var decryptor = AES.createDecryptor(key, cfg);
          return decryptor.finalize(ciphertext);
        }
      };

      return C;
    })();

    // --- 辅助方法 ---
    function doDecrypt(cipherText, key, iv, mode) {
      if (!cipherText || !key) return '';
      var modeObj = (mode && mode.toUpperCase() === 'CBC') ? MiniCrypto.mode.CBC : MiniCrypto.mode.ECB;
      var cfg = { mode: modeObj, padding: MiniCrypto.pad.Pkcs7 };
      if (iv) cfg.iv = iv;
      var decrypted = MiniCrypto.AES.decrypt(cipherText, key, cfg);
      return decrypted.toString(MiniCrypto.enc.Utf8);
    }

    function doEncrypt(plainText, key, iv, mode) {
      if (!plainText || !key) return '';
      var modeObj = (mode && mode.toUpperCase() === 'CBC') ? MiniCrypto.mode.CBC : MiniCrypto.mode.ECB;
      var cfg = { mode: modeObj, padding: MiniCrypto.pad.Pkcs7 };
      if (iv) cfg.iv = iv;
      return MiniCrypto.AES.encrypt(plainText, key, cfg).toString();
    }

    function getMatchedRule(url) {
      if (!url || typeof url !== 'string' || !window.__aesRules) return null;
      var fullUrl = url.indexOf('://') === -1 ? (location.origin + (url.indexOf('/') === 0 ? '' : '/') + url) : url;
      for (var i = 0; i < window.__aesRules.length; i++) {
        var rule = window.__aesRules[i];
        if (!rule.key || !rule.urlKeywords) continue;
        var kws = rule.urlKeywords.split(',');
        for (var j = 0; j < kws.length; j++) {
          var kw = kws[j].trim();
          if (kw && (fullUrl.indexOf(kw) !== -1 || location.href.indexOf(kw) !== -1)) return rule;
        }
      }
      return null;
    }

    function byPath(o, p) {
      if (!p || !o) return undefined;
      var parts = p.replace(/\[(\w+)\]/g, '.$1').replace(/^\./, '').split('.');
      return parts.reduce(function(a, k) { return (a == null) ? undefined : a[k]; }, o);
    }

    function tryParseJSON(str) {
      try { return JSON.parse(str); } catch(e) { return null; }
    }

    function handleDecryptAndLog(rule, type, url, rawData) {
      if (!rawData || typeof rawData !== 'string') return;
      var fieldPath = (type === 'REQ') ? rule.reqField : rule.resField;
      var key = rule.key, iv = rule.iv, mode = rule.mode || 'ECB';
      var cipher = null;

      var json = tryParseJSON(rawData);
      if (json && fieldPath) {
        cipher = byPath(json, fieldPath);
      } else if (!fieldPath) {
        if (!json) cipher = rawData.trim();
      }

      if (cipher && typeof cipher === 'string') {
        try {
          var decryptedStr = doDecrypt(cipher, key, iv, mode);
          if (decryptedStr) {
            var parsed = tryParseJSON(decryptedStr) || decryptedStr;
            var tag = type === 'REQ' ? '⬆️ [AES 请求体解密]' : '⬇️ [AES 响应体解密]';
            console.log(
              '%c' + tag + ' %c' + (rule.name ? '[' + rule.name + '] ' : '') + url,
              'color:#fff;background:#2e7d32;padding:2px 6px;border-radius:3px;font-weight:bold;',
              'color:#1565c0;font-weight:bold;',
              '\n\n⭕️ 解密结果：\n', parsed
            );
          }
        } catch(e) {
          console.warn('[AES] ❎ 解密异常:', url, e);
        }
      }
    }

    // --- Hook XMLHttpRequest ---
    var OrigXHR = window.XMLHttpRequest;
    function CustomXHR() {
      var xhr = new OrigXHR();
      var reqUrl = '', matchedRule = null;
      var open = xhr.open;
      xhr.open = function(m, u) {
        reqUrl = u;
        matchedRule = getMatchedRule(u);
        return open.apply(this, arguments);
      };
      var send = xhr.send;
      xhr.send = function(body) {
        if (matchedRule && body && typeof body === 'string') {
          handleDecryptAndLog(matchedRule, 'REQ', reqUrl, body);
        }
        this.addEventListener('readystatechange', function() {
          if (matchedRule && this.readyState === 4 && (this.status === 200 || this.status === 0)) {
            handleDecryptAndLog(matchedRule, 'RES', reqUrl, this.responseText);
          }
        });
        return send.apply(this, arguments);
      };
      return xhr;
    }
    window.XMLHttpRequest = CustomXHR;

    // --- Hook Fetch ---
    var origFetch = window.fetch;
    window.fetch = async function() {
      var req = arguments[0];
      var url = typeof req === 'string' ? req : (req && req.url ? req.url : '');
      var matchedRule = getMatchedRule(url);
      var init = arguments[1];

      if (matchedRule && init && init.body && typeof init.body === 'string') {
        handleDecryptAndLog(matchedRule, 'REQ', url, init.body);
      }

      var resp = await origFetch.apply(this, arguments);
      if (matchedRule) {
        try {
          var c = resp.clone();
          var t = await c.text();
          handleDecryptAndLog(matchedRule, 'RES', url, t);
        } catch (e) {}
      }
      return resp;
    };

    // --- 全局调试工具 ---
    window.aes = function(cipherText, key, iv, mode) {
      var rule = (window.__aesRules && window.__aesRules[0]) || {};
      var finalKey = key || rule.key;
      var finalIv = iv !== undefined ? iv : rule.iv;
      var finalMode = mode || rule.mode || 'ECB';
      return doDecrypt(cipherText, finalKey, finalIv, finalMode);
    };

    window.aesEncrypt = function(plainText, key, iv, mode) {
      var rule = (window.__aesRules && window.__aesRules[0]) || {};
      var finalKey = key || rule.key;
      var finalIv = iv !== undefined ? iv : rule.iv;
      var finalMode = mode || rule.mode || 'ECB';
      return doEncrypt(plainText, finalKey, finalIv, finalMode);
    };

    window.aesConfig = function() {
      window.dispatchEvent(new CustomEvent('__OPEN_AES_CONFIG__'));
    };

    console.log('[cryptoAES] 双向拦截器与加解密引擎已就绪');
  }

  // 4. 注入逻辑
  function injectRunner() {
    var s = document.createElement('script');
    s.textContent = '(' + pageContextRunner.toString() + ')(' + JSON.stringify(JSON.stringify(currentRules)) + ');';
    (document.head || document.documentElement).appendChild(s);
    s.remove();
  }

  function pageMatchesAny() {
    var href = location.href;
    for (var i = 0; i < currentRules.length; i++) {
      var kws = (currentRules[i].urlKeywords || '').split(',');
      for (var j = 0; j < kws.length; j++) {
        var kw = kws[j].trim();
        if (kw && href.indexOf(kw) !== -1) return true;
      }
    }
    return false;
  }

  if (pageMatchesAny() || currentRules.length > 0) {
    injectRunner();
  }

  // 5. 设置面板 UI（现代响应式设计，完美适配 PC 与 iOS/Stay）
  try {
    var NS = 'aesdbg';
    var css = [
      '#' + NS + '-panel{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:2147483647;',
      'width:92vw;max-width:380px;background:#fff;color:#222;border:1px solid #ddd;border-radius:12px;',
      'padding:16px;font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;',
      'box-shadow:0 8px 30px rgba(0,0,0,.25);box-sizing:border-box;max-height:90vh;overflow-y:auto}',
      '#' + NS + '-panel *{box-sizing:border-box}',
      '#' + NS + '-panel h3{margin:0 0 12px;font-size:15px;display:flex;justify-content:space-between;align-items:center}',
      '#' + NS + '-panel .close{cursor:pointer;color:#999;font-size:18px;line-height:1;padding:4px}',
      '#' + NS + '-panel .tabs{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px;margin-bottom:10px}',
      '#' + NS + '-panel .tab{padding:4px 10px;border-radius:6px;background:#f0f0f0;font-size:12px;cursor:pointer;white-space:nowrap}',
      '#' + NS + '-panel .tab.active{background:#222;color:#fff;font-weight:600}',
      '#' + NS + '-panel .tab-add{padding:4px 8px;border-radius:6px;background:#e0e0e0;cursor:pointer;font-weight:bold}',
      '#' + NS + '-panel label{display:block;font-weight:600;margin-top:8px;font-size:12px;color:#333}',
      '#' + NS + '-panel input, #' + NS + '-panel select{width:100%;padding:7px 8px;margin:4px 0;',
      'border:1px solid #ccc;border-radius:6px;font-family:monospace;font-size:12px;background:#fafafa}',
      '#' + NS + '-panel input:focus, #' + NS + '-panel select:focus{border-color:#222;outline:none;background:#fff}',
      '#' + NS + '-panel .row{display:flex;gap:8px}',
      '#' + NS + '-panel .row > div{flex:1}',
      '#' + NS + '-panel .btn-group{display:flex;gap:8px;margin-top:14px}',
      '#' + NS + '-panel button{flex:1;padding:8px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600}',
      '#' + NS + '-panel .btn-save{background:#222;color:#fff}',
      '#' + NS + '-panel .btn-del{background:#ff4d4f;color:#fff}',
      '#' + NS + '-panel .hint{color:#888;font-size:11px;margin-top:8px;text-align:center;min-height:16px}'
    ].join('');

    var style = document.createElement('style');
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);

    var activeRuleIndex = 0;

    function buildPanel() {
      var existing = document.getElementById(NS + '-panel');
      if (existing) existing.remove();

      currentRules = loadRules();
      if (activeRuleIndex >= currentRules.length) activeRuleIndex = 0;

      var panel = document.createElement('div');
      panel.id = NS + '-panel';

      function renderContent() {
        var rule = currentRules[activeRuleIndex] || {
          name: '规则 1', urlKeywords: '', mode: 'ECB', key: '', iv: '', resField: '', reqField: ''
        };

        var tabsHtml = currentRules.map(function(r, idx) {
          return '<span class="tab ' + (idx === activeRuleIndex ? 'active' : '') + '" data-idx="' + idx + '">' +
            (r.name || '规则 ' + (idx + 1)) + '</span>';
        }).join('') + '<span class="tab-add" title="添加新规则">+</span>';

        panel.innerHTML =
          '<h3><span>🔑 AES 解密配置</span><span class="close">✕</span></h3>' +
          '<div class="tabs">' + tabsHtml + '</div>' +
          '<label>规则名称</label>' +
          '<input type="text" class="inp-name" placeholder="如：测试环境" value="' + (rule.name || '') + '" />' +
          '<label>URL 关键词 (逗号分隔)</label>' +
          '<input type="text" class="inp-url" placeholder="如：api.example.com,/api/user" value="' + (rule.urlKeywords || '') + '" />' +
          '<div class="row">' +
            '<div>' +
              '<label>加密模式</label>' +
              '<select class="inp-mode">' +
                '<option value="ECB"' + (rule.mode === 'ECB' ? ' selected' : '') + '>AES-ECB</option>' +
                '<option value="CBC"' + (rule.mode === 'CBC' ? ' selected' : '') + '>AES-CBC</option>' +
              '</select>' +
            '</div>' +
            '<div class="iv-box" style="' + (rule.mode === 'CBC' ? '' : 'display:none;') + '">' +
              '<label>IV 偏移量 (16位)</label>' +
              '<input type="text" class="inp-iv" placeholder="CBC 模式必填" value="' + (rule.iv || '') + '" />' +
            '</div>' +
          '</div>' +
          '<label>AES 密钥 (Key)</label>' +
          '<input type="text" class="inp-key" placeholder="16/24/32 位密钥" value="' + (rule.key || '') + '" />' +
          '<label>响应解密字段 (留空则全包解密)</label>' +
          '<input type="text" class="inp-res" placeholder="如：data.payload 或 data.list[0].cipher" value="' + (rule.resField || '') + '" />' +
          '<label>请求体解密字段 (可选)</label>' +
          '<input type="text" class="inp-req" placeholder="如：encryptData (拦截 POST 发包)" value="' + (rule.reqField || '') + '" />' +
          '<div class="btn-group">' +
            '<button type="button" class="btn-save">保存生效</button>' +
            (currentRules.length > 1 ? '<button type="button" class="btn-del">删除此规则</button>' : '') +
          '</div>' +
          '<div class="hint"></div>';

        bindEvents();
      }

      function bindEvents() {
        panel.querySelector('.close').onclick = function() { panel.remove(); };

        // 标签切换
        var tabs = panel.querySelectorAll('.tab');
        tabs.forEach(function(t) {
          t.onclick = function() {
            activeRuleIndex = parseInt(this.getAttribute('data-idx'), 10);
            renderContent();
          };
        });

        // 添加规则
        var addBtn = panel.querySelector('.tab-add');
        if (addBtn) {
          addBtn.onclick = function() {
            currentRules.push({
              id: 'rule_' + Date.now(),
              name: '规则 ' + (currentRules.length + 1),
              urlKeywords: '',
              mode: 'ECB',
              key: '',
              iv: '',
              resField: '',
              reqField: ''
            });
            activeRuleIndex = currentRules.length - 1;
            renderContent();
          };
        }

        // 模式切换显示/隐藏 IV
        var modeSelect = panel.querySelector('.inp-mode');
        var ivBox = panel.querySelector('.iv-box');
        modeSelect.onchange = function() {
          ivBox.style.display = this.value === 'CBC' ? 'block' : 'none';
        };

        // 删除规则
        var delBtn = panel.querySelector('.btn-del');
        if (delBtn) {
          delBtn.onclick = function() {
            if (currentRules.length <= 1) return;
            currentRules.splice(activeRuleIndex, 1);
            activeRuleIndex = Math.max(0, activeRuleIndex - 1);
            storage.set('rules', currentRules);
            injectRunner();
            renderContent();
          };
        }

        // 保存规则
        var saveBtn = panel.querySelector('.btn-save');
        var hint = panel.querySelector('.hint');
        saveBtn.onclick = function() {
          var name = panel.querySelector('.inp-name').value.trim();
          var url = panel.querySelector('.inp-url').value.trim();
          var mode = panel.querySelector('.inp-mode').value;
          var iv = panel.querySelector('.inp-iv') ? panel.querySelector('.inp-iv').value.trim() : '';
          var key = panel.querySelector('.inp-key').value.trim();
          var res = panel.querySelector('.inp-res').value.trim();
          var req = panel.querySelector('.inp-req').value.trim();

          if (!key) { hint.textContent = '❌ AES 密钥不能为空'; return; }
          if (mode === 'CBC' && !iv) { hint.textContent = '❌ CBC 模式必须填写 IV 偏移量'; return; }

          currentRules[activeRuleIndex] = {
            id: currentRules[activeRuleIndex].id || ('rule_' + Date.now()),
            name: name || ('规则 ' + (activeRuleIndex + 1)),
            urlKeywords: url,
            mode: mode,
            iv: iv,
            key: key,
            resField: res,
            reqField: req
          };

          storage.set('rules', currentRules);
          injectRunner();

          hint.textContent = '✅ 保存成功，规则已实时生效！';
          setTimeout(function() { panel.remove(); }, 700);
        };
      }

      renderContent();
      (document.body || document.documentElement).appendChild(panel);
    }

    // 菜单命令注册
    if (typeof GM_registerMenuCommand !== 'undefined') {
      GM_registerMenuCommand('🔑 设置 AES 解密配置', function() {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildPanel);
        else buildPanel();
      });
    }

    // 控制台事件监听 (支持页面直接调用 window.aesConfig())
    window.addEventListener('__OPEN_AES_CONFIG__', function() {
      buildPanel();
    });

  } catch (e) {
    console.error('[cryptoAES] 面板初始化失败:', e);
  }
})();
