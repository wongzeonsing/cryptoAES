# cryptoAES

油猴（Tampermonkey）/ Stay 用户脚本，自动拦截 XHR 与 fetch 请求与响应，解密 AES 加密字段并高亮输出到控制台。

完全兼容桌面端浏览器（Chrome / Edge / Firefox / Safari 油猴）与移动端浏览器（iOS Stay / Safari）。

---

## 🚀 安装

在油猴或 Stay 中打开以下脚本地址即可自动提示安装：

```
https://raw.githubusercontent.com/wongzeonsing/cryptoAES/main/cryptoAES.user.js
```

---

## ✨ 核心特性

- 🛡️ **双端极致兼容**：内置精简加解密核心，零外部 CDN 网络请求，彻底免疫严格 CSP（内容安全策略）拦截。
- 🔄 **双向流量拦截**：同时支持 **Response 响应体** 与 **Request 请求体 (POST/PUT 发包)** 拦截解密。
- 🔐 **全模式支持**：支持 **AES-ECB** 与 **AES-CBC**（支持自定义 16 位 IV 偏移量），支持 Base64 与 Hex 密文。
- 📑 **多规则管理**：支持针对不同网站/接口配置多套规则，随时切换与管理。
- 🎯 **灵活字段提取**：支持点分嵌套路径与数组下标（如 `data.payload`、`data.list[0].cipher`），支持纯文本密文免路径自动降级解密。
- 🛠️ **便捷控制台调试**：挂载全局辅助方法，支持在 DevTools 控制台随时手动加密、解密和唤起配置面板。

---

## ⚙️ 配置与使用

### 1. 打开配置面板
- **方式 A（油猴 / Stay 扩展菜单）**：点击油猴或 Stay 菜单项 `🔑 设置 AES 解密配置`。
- **方式 B（控制台直达）**：在页面控制台直接执行 `window.aesConfig()` 即可呼出面板（移动端更方便）。

### 2. 配置字段说明
- **规则名称**：用于在控制台日志中标识接口所属规则。
- **域名/URL 关键词**：匹配该关键词的请求才会触发拦截（支持英文逗号分隔多个）。
- **加密模式**：支持 `AES-ECB` 或 `AES-CBC`。选择 CBC 时需填写 **IV 偏移量**。
- **AES 密钥 (Key)**：16/24/32 位密钥。
- **响应解密字段**：提取响应 JSON 中加密字段的点分路径（留空时，若响应为纯密文将自动整包解密）。
- **请求体解密字段 (可选)**：拦截前端 POST 请求参数中的加密字段。

---

## 🧰 控制台实用工具

脚本向页面挂载了以下全局函数，方便直接在浏览器 DevTools 控制台进行调试与模拟：

```js
// 1. 手动解密（参数可选，默认使用当前规则的 key / iv / mode）
window.aes("Base64或Hex密文", [key], [iv], [mode]);

// 2. 手动加密（方便构造测试请求参数发包）
window.aesEncrypt("明文字符串或JSON", [key], [iv], [mode]);

// 3. 打开配置面板
window.aesConfig();
```

---

## 🔄 自动更新

脚本配置了 `@updateURL` 与 `@downloadURL`，新版本推送至 GitHub main 分支后，油猴 / Stay 会自动检测并更新。
