// ==UserScript==
// @name         AES 解密响应字段
// @namespace    http://tampermonkey.net/
// @version      2026.08.24
// @description  解密接口返回值并打印，支持自定义域名/密钥/字段路径
// @match        *://*/*
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @run-at       document-start
// @updateURL   https://raw.githubusercontent.com/wongzeonsing/cryptoAES/main/cryptoAES.user.js
// @downloadURL https://raw.githubusercontent.com/wongzeonsing/cryptoAES/main/cryptoAES.user.js
// @version     2026.08.24
// ==/UserScript==

(function() {
  'use strict';

  // Storage: GM_* or localStorage fallback
  var storage = {
    get: function(k, d) {
      if (typeof GM_getValue !== 'undefined') return GM_getValue(k, d);
      try { var v = localStorage.getItem('aes_' + k); return v === null ? d : v; } catch(e) { return d; }
    },
    set: function(k, v) {
      if (typeof GM_setValue !== 'undefined') return GM_setValue(k, v);
      try { localStorage.setItem('aes_' + k, v); } catch(e) {}
    }
  };

  var urlKeywords = storage.get('urlKeywords', '');
  var currentKey = storage.get('aesKey', '');
  var currentField = storage.get('aesField', '');

  function pageMatches() {
    if (!urlKeywords) return false;
    var kws = urlKeywords.split(',');
    var href = location.href;
    for (var i = 0; i < kws.length; i++) {
      var kw = kws[i].trim();
      if (kw && href.indexOf(kw) !== -1) return true;
    }
    return false;
  }

  // Page-context interception (serialized via toString(), no closure refs)
  function pageScript(key, field, keywords) {
    if (window.__aesHooksInstalled) {
      window.__aesKey = key;
      window.__aesField = field;
      window.__aesKeywords = keywords;
      return;
    }
    window.__aesHooksInstalled = true;
    window.__aesKey = key;
    window.__aesField = field;
    window.__aesKeywords = keywords;

    function decrypt(ct) {
      var k = CryptoJS.enc.Utf8.parse(window.__aesKey);
      var d = CryptoJS.AES.decrypt(
        { ciphertext: CryptoJS.enc.Base64.parse(String(ct).replace(/[\r\n]/g, '')) },
        k, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
      );
      return d.toString(CryptoJS.enc.Utf8);
    }

    function hit(url) {
      if (typeof url !== 'string') return false;
      var kws = window.__aesKeywords.split(',');
      for (var i = 0; i < kws.length; i++) {
        var kw = kws[i].trim();
        if (kw && url.indexOf(kw) !== -1) return true;
      }
      return false;
    }

    function byPath(o, p) {
      if (!p || !o) return undefined;
      return p.split('.').reduce(function(a, k) { return a == null ? undefined : a[k]; }, o);
    }

    function tryDecrypt(url, text) {
      try {
        var json = JSON.parse(text);
        var enc = byPath(json, window.__aesField);
        if (enc) {
          var d = decrypt(enc);
          var p = JSON.parse(d);
          console.log('✅ 解密成功：\n' + url + '\n\n⭕️ 解密结果：\n', p);
        }
      } catch (e) {
        console.log('[AES] ❎', url, e);
      }
    }

    // Hook XMLHttpRequest
    var OrigXHR = window.XMLHttpRequest;
    function CustomXHR() {
      var xhr = new OrigXHR();
      var reqUrl = '';
      var open = xhr.open;
      xhr.open = function(m, u) { if (hit(u)) reqUrl = u; return open.apply(this, arguments); };
      var send = xhr.send;
      xhr.send = function() {
        this.addEventListener('readystatechange', function() {
          if (reqUrl && this.readyState === 4 && (this.status === 200 || this.status === 0))
            tryDecrypt(reqUrl, this.responseText);
        });
        return send.apply(this, arguments);
      };
      return xhr;
    }
    window.XMLHttpRequest = CustomXHR;

    // Hook fetch
    var origFetch = window.fetch;
    window.fetch = async function() {
      var req = arguments[0];
      var url = typeof req === 'string' ? req : req.url;
      var matched = hit(url);
      var resp = await origFetch.apply(this, arguments);
      if (matched) {
        try { var c = resp.clone(); var t = await c.text(); tryDecrypt(url, t); } catch (e) {}
      }
      return resp;
    };

    window.aes = decrypt;
    console.log('[AES] 拦截器已注入');
  }

  // Inject into page context
  var injected = false;

  function injectPage() {
    var s = document.createElement('script');
    s.textContent = '(' + pageScript.toString() + ')(' +
      JSON.stringify(currentKey) + ',' +
      JSON.stringify(currentField) + ',' +
      JSON.stringify(urlKeywords) + ')';
    (document.head || document.documentElement).appendChild(s);
    s.remove();
  }

  function activate() {
    if (injected) { injectPage(); return; }
    var cj = document.createElement('script');
    cj.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
    cj.onload = function() { injected = true; injectPage(); };
    cj.onerror = function() { console.error('[AES] CryptoJS 加载失败'); };
    (document.head || document.documentElement).appendChild(cj);
  }

  if (pageMatches()) activate();

  // Settings panel (always available)
  try {
    var NS = 'aesdbg';
    var css = [
      '#' + NS + '-panel{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:2147483647;',
      'width:280px;background:#fff;color:#222;border:1px solid #ccc;border-radius:8px;',
      'padding:12px;font:13px/1.5 system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.3)}',
      '#' + NS + '-panel input{width:100%;box-sizing:border-box;padding:6px;margin:4px 0;',
      'border:1px solid #bbb;border-radius:4px;font-family:monospace}',
      '#' + NS + '-panel button{margin-top:6px;padding:6px 10px;border:none;border-radius:4px;',
      'background:#222;color:#fff;cursor:pointer}',
      '#' + NS + '-panel .hint{color:#888;font-size:11px;margin-top:6px}',
      '#' + NS + '-panel .close{position:absolute;right:8px;top:6px;cursor:pointer;color:#999}',
      '#' + NS + '-panel label{display:block;font-weight:bold;margin-top:8px}',
    ].join('');
    var style = document.createElement('style');
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);

    function buildPanel() {
      if (document.getElementById(NS + '-panel')) document.getElementById(NS + '-panel').remove();
      var panel = document.createElement('div');
      panel.id = NS + '-panel';
      panel.innerHTML =
        '<span class="close">✕</span>' +
        '<label>域名/URL 关键词</label>' +
        '<input type="text" placeholder="example.com" />' +
        '<label>AES 密钥</label>' +
        '<input type="text" placeholder="16/24/32 位密钥" />' +
        '<label>解析字段路径</label>' +
        '<input type="text" placeholder="result_info.encrypt" />' +
        '<button type="button">保存</button>' +
        '<div class="hint"></div>';
      (document.body || document.documentElement).appendChild(panel);
      var inputs = panel.querySelectorAll('input');
      var urlInput = inputs[0], keyInput = inputs[1], fieldInput = inputs[2];
      var saveBtn = panel.querySelector('button');
      var hint = panel.querySelector('.hint');
      panel.querySelector('.close').addEventListener('click', function() { panel.remove(); });
      urlInput.value = urlKeywords;
      keyInput.value = currentKey;
      fieldInput.value = currentField;
      saveBtn.addEventListener('click', function() {
        var d = urlInput.value.trim();
        var k = keyInput.value.trim();
        var f = fieldInput.value.trim();
        if (!d) { hint.textContent = 'URL 关键词不能为空'; return; }
        if (!k) { hint.textContent = '密钥不能为空'; return; }
        if (!f) { hint.textContent = '字段路径不能为空'; return; }
        urlKeywords = d; storage.set('urlKeywords', d);
        currentKey = k; storage.set('aesKey', k);
        currentField = f; storage.set('aesField', f);
        activate();
        hint.textContent = '✅ 已保存';
        setTimeout(function() { panel.remove(); }, 600);
      });
    }

    if (typeof GM_registerMenuCommand !== 'undefined') {
      GM_registerMenuCommand('🔑 设置 AES 解密配置', function() {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildPanel);
        else buildPanel();
      });
    }
  } catch (e) { console.error('[AES] 设置面板失败:', e); }
})();
