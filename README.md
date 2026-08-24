# cryptoAES

油猴/Stay 用户脚本，自动拦截 XHR/fetch 响应，解密 AES 加密字段并打印到控制台。

## 安装

在油猴或 Stay 中打开以下地址，会自动弹出安装提示：

```
https://raw.githubusercontent.com/wongzeonsing/cryptoAES/main/cryptoAES.user.js
```

## 配置

安装后通过油猴/Stay 菜单「🔑 设置 AES 解密配置」打开设置面板，填写三项：

1. **域名/URL 关键词**：匹配的 URL 才会激活拦截（逗号分隔多个关键词）
2. **AES 密钥**：16/24/32 位
3. **解析字段路径**：点分路径，如 `a.b.c`

配置存储在本地（油猴用 `GM_*`，Stay 回退 `localStorage`），不在脚本文件中。

## 手动解密

在页面控制台输入：

```js
window.aes("Base64密文")
```

返回解密后的明文字符串。

## 自动更新

脚本通过 `@updateURL` / `@downloadURL` 自动检查 GitHub 更新，新版本推送后油猴/Stay 会自动拉取。
