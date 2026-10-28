# WAA / BotGuard 纯 Node VM 逆向破解与全量环境伪装技术文档

> 日期：2026-10-27
> 项目：`/root/waavm-ref/waa-runtime`
> 声明：本文档仅记录逆向工程方法论、字节码虚拟机（VM）架构、加密原语、差分实验过程与沙箱设计，不包含任何 Cookie、Authorization、API Key 或敏感凭据。

---

## 0. 核心成果概览

本次逆向工程彻底打通了 Google AI Studio (`MakerSuiteService/GenerateContent`) 所使用的 **WAA / BotGuard 字节码虚拟机（`vMas` / `cizw` / `Qoo_` / `yoc_` 系列）在纯 Node.js（`node:vm`）下的无浏览器执行与有效证明（Proof）铸造**。

- **摆脱浏览器依赖**：不再需要后台常驻 Chrome / Xvfb / CDP，直接在 Node.js 进程内完成 `Waa/Create` 动态拉取 Challenge $\rightarrow$ 运行 BotGuard 字节码 VM $\rightarrow$ 产出 `V` 模式 `!proof` $\rightarrow$ 调用 `GenerateContent` 返回 `HTTP 200 OK`。
- **资源与性能突破**：
  - **内存占用**：从单 Chrome 实例的 `800 ~ 1,003 MB` PSS（8~11 个进程）降至 **`135.5 MB` RSS（V8 堆仅 `35.9 MB`）**，降低约 **86%**。
  - **空闲 CPU**：从 Chrome SwiftShader 软渲染的 `30% ~ 45%` 降至 **`0%`**。
  - **冷启动耗时**：从 Chrome 页面预热的 `11.5 s ~ 25.3 s` 降至 **`1.0 s ~ 1.5 s`**。
  - **热态单次 Mint 耗时**：仅 **`27 ms ~ 41 ms`**。

---

## 1. 背景与早期三大误区的推翻

在接手本阶段逆向之前，本地仓库的实验卡在两个表象问题上：
1. 同一份浏览器抓包的 `Waa/Create` Challenge，在真浏览器 `bscframe` 中产出 `V` 模式（`S = 100`，`HTTP 200`），而在本地 `node:vm` 中却落入 `F` 模式（`S = 90`，`HTTP 403`）。
2. 即使偶发通过调用 `service.iA()` 让本地产出 `V` 模式证明，提交给 `GenerateContent` 依然 100% 返回 `HTTP 403`。

早期分析曾提出三个推断，我们在本次逆向中逐一用实验将其推翻：

| 早期推断 | 本次逆向证伪结论 | 真实根因 |
|---|---|---|
| **误区 1**：“外层沙箱的 `createElement` / `createEvent` 钩子统计到 0 次调用，说明 VM 根本没调 DOM，不是环境缺失问题。” | **错误**。VM 在 `pc = 8522` 处通过 `tU` 二阶段自举二次 `eval` 了全新的解释器闭包，且所有 DOM 探针都在 `iframe.contentWindow`（`bscframe`）上下文中通过动态解密的字符串调用，早期外层静态钩子根本未覆盖该路径。 | 二阶段字节码执行了上百次 `window`、`navigator`、`document`、`div.style`、`img`、`MouseEvents` 探针。 |
| **误区 2**：“本地 `V` 证明中的 `0x0F` 段（如 `[22, 88, 15]` 或 `[30, 42, 38, 126]`）是 V 模式的正常状态段。” | **错误**。对比真浏览器 `200 OK` 的 `V` 证明可发现：**合法的 `V` 证明中完全不存在 `0x0F` 段（长度为 0）**。 | `0x0F`（对应 VM 内部寄存器 `reg 371`）是 VM 的 **`nd` 异常上报器**！一旦字节码执行抛错，`nd` 就会把 `[错误码, pc_hi, pc_lo]` 写入 `0x0F`，并把沙箱的 `Error.stack` 塞进 `0x99` 段上报给服务端。 |
| **误区 3**：“Node.js 拉取的 `Waa/Create` Challenge 在服务端被打了低信誉标记（Challenge Provenance Gate），只有真浏览器拉取的 Challenge 才能 200。” | **错误**。Node 拉取的 Challenge 之所以 403，是因为每次 `Waa/Create` 返回的字节码都会**随机抽取不同的 WebIDL 构造器与属性名**；缓存的旧 Challenge 碰巧没抽到缺失属性，而新拉取的 Challenge 抽到了沙箱缺失的构造器（如 `WeakMap`、`leaveAdInterestGroup`、`window.when`）。 | 补齐 Chrome 151 全量属性/原型 Schema 后，Node.js 直接通过 `fetch` 拉取的全新 Challenge 连续 100% 返回 `HTTP 200 OK`。 |

---

## 2. 逆向工具链构建：如何无损透视自校验 VM

### 2.1 为什么不能直接修改 VM 源码插桩（`pc = 25797..25997` 自校验）

从 `iframe-eval.js` 提取出的 VM 源码（约 62 KB）在字节码执行的最后阶段（如 `cizw` 的 `pc = 25797..25997`），会依次对 VM 核心内部函数调用 `.toString()`：

```javascript
Ld.toString() -> JU(...)
k5.toString() -> JU(...)
ul.toString() -> JU(...)
XX.toString() -> JU(...)
S.toString()  -> JU(...)
```

随后在 `pc = 25997` 调用 `GX.call(this, 26, 6, 208030)`，用这 5 个函数源码字符串的 `JU` 哈希值更新流密码密钥寄存器 `reg 169`！
这意味着：**任何直接修改 `ul`、`XX`、`Ld`、`k5` 或主循环函数源码的 `console.log` 插桩，都会改变 `.toString()` 的字符序列，导致末尾流密码密钥雪崩，解密出乱码并崩溃**。

### 2.2 V8 Inspector 条件恒假断点（Non-Intrusive Tracing）

为了在不改动一字节源码的前提下完整记录 VM 的每条指令、每次寄存器读写和每次 `0x99` 遥测写入，我们使用 Node.js 内置的 `node:inspector` 模块：

1. 开启 `Debugger.enable` 与 `Debugger.setInstrumentationBreakpoint({ instrumentation: 'beforeScriptExecution' })`。
2. 当 `iframe-eval.js`（或二阶段 `eval` 脚本）加载暂停时，通过 `Debugger.getScriptSource` 定位目标语句的行列号（如 `ul` 入口 `e=H(I,v),v==291`、属性读取 `W(l,B,f[q])`、函数调用 `W(Z,m.g0,q.apply(B,m.N))`、异常捕获 `nd`）。
3. 调用 `Debugger.setBreakpoint` 注入**条件恒为 `false` 的日志表达式**：
   ```javascript
   condition: 'window.__writes.push({ fn: "ul", pc: H(I,153)>>3, reg: v, tag: V, bytes: Array.from(S||[]) }), false'
   ```
   V8 引擎每次执行到该位置时都会求值 `condition`（完成日志收集），又因为表达式返回 `false`，V8 不会触发暂停，也不会修改任何函数体的 `.toString()` 原文。

---

## 3. 第一道关卡：攻克 `F -> V` 分水岭（`pc = 10776` 动态密钥派生）

### 3.1 外层 TLV 与流密码结构

`!proof` 去掉首字符 `!` 后经 Base64URL 解码得到字节流 `P`：
- 前 5 字节编码了前置区（Prelude）结束偏移：
  $$S = ((P[3] \oplus P[1]) \ll 8) \mid (P[4] \oplus P[1])$$
  - $S = 90$（`0x5a`）：`F` 模式（中途因解密密钥错误或未捕获异常提前终止）。
  - $S = 100$（`0x64`）：`V` 模式（完整走完字节码全流程）。
- 偏移 $S$ 之后为分段 TLV 区与末尾 288 字节签名块：
  - `0x68`（固定 2 字节）：版本/标志位。
  - `0x0F`（2 字节长度 + 数据，对应 `reg 371`）：`nd` 异常上报段（正常 `V` 证明中**无此段**）。
  - `0x7E`（2 字节长度 + 数据，对应 `reg 330` / `reg 49`）：字节码基本块执行轨迹（Control-Flow Trace，正常为 75 字节）。
  - `0x99`（2 字节长度 + 数据，对应 `reg 291` / `reg 179`）：加密的环境遥测 TLV 流（正常约 940~980 字节）。

### 3.2 `pc = 10193..10776`：环境探针如何决定后续字节码能否解密

通过 `node:inspector` 追踪 `cizw` 字节码在崩溃前的最后几百条指令，我们还原了 `F` 模式的真正成因：

1. **二阶段自举（`pc = 8522` / `bitPc = 68176`）**：VM 解密 `tU[13]` 并调用 `eval(Q)`，将新的解释器函数簇替换进闭包。
2. **第一组 3 路 `typeof` 探针拼接（`pc = 10193..10759`）**：
   - 字节码解密出盐值 `"6qlsvA"`，依次读取：
     - `typeof document.createElement('img').removeChild`
     - `typeof document.createEvent('MouseEvents').screenX`
     - `typeof document.createElement('img').scrollTop`
   - 在真实 Chrome 151 中，三者拼接为 `"6qlsvAfunctionnumbernumber"`（26 字节）。
   - 而在未补齐的本地沙箱中，`document.createEvent('MouseEvents')` 返回的简易对象没有 `screenX` 属性，导致拼接结果变成了 `"6qlsvAfunctionundefinednumber"`！
3. **流密码动态 Re-key（`pc = 10776`）**：
   - 字节码将上述探针字符串送入 `JU` 哈希，并在 `pc = 10776` 调用 `GX.call(this, 26, 6, 86264)`，**直接用该哈希值覆盖流密码密钥寄存器 `reg 169`**，随后跳转至 `bitPc = 86264`（`pc = 10783`）。
   - 因为本地沙箱算出的哈希值错误，`pc = 10783` 之后的指令字节流 `HB()` 用错误的密钥解出了乱码指令，在 7 个字节后的 `pc = 10790`（`0x2a26`）尝试读取未初始化的寄存器 `reg 126`（`0x7e`），抛出内部异常 `[bl, 30, 126]`！
   - `nd` 捕获该异常，将 `[0x1e, 0x2a, 0x26, 0x7e]` 写入 `0x0F` 段，终止后续约 380 个 `tU` 字符串的解密，最终产出 `F` 模式证明。

补齐探针类型后，VM 顺利通过 `pc = 10783` 解密出后续全部指令，且 `0x0F` 异常段彻底消失，稳定进入 `S = 100` 的 `V` 模式。

---

## 4. 第二道关卡：用分段替换 Oracle 定位为什么本地 `V` 证明仍被 `403`

进入无异常（无 `0x0F` 段）的 `V` 模式后，直接提交给 `GenerateContent` 仍然返回 `HTTP 403`。此时证明长度（~1550 chars）、模式（`V`）、TLV 段类型（`0x68`、`0x7E`、`0x99`）均与真浏览器一致。到底哪一段、哪几个字节被 Google 服务端拒绝？

### 4.1 外层分段替换实验（`oracle_section_swap.js`）

我们以同一份 `page-challenge-live.bin` 和同一个 `prompt`（相同 SHA-256 content digest），分别在真浏览器（Oracle，返回 `200 OK`）和本地 Node VM（Local，返回 `403`）各铸造一条 `V` 证明，然后做交叉嫁接实验：

| 实验编号 | 嫁接方式 | `GenerateContent` 响应 | 结论 |
|---|---|---|---|
| **Exp 1** | 真浏览器 Proof，仅把 `0x7E`（75B 控制流轨迹）替换为本地 Node VM 的 `0x7E` | **`HTTP 200 OK`** | 本地 Node VM 的字节码控制流轨迹 `0x7E` **100% 合法**！ |
| **Exp 2** | 真浏览器 Proof，仅把 `0x99`（加密遥测段）替换为本地 Node VM 的 `0x99` | **`HTTP 403`** | 本地 `0x99` 段中存在被服务端判定为伪造/异常的遥测记录。 |
| **Exp 3** | 本地 Node VM Proof（保留本地 Prelude + 本地 `0x68` + 本地 `0x7E` + **本地末尾 288B 签名块**），仅把 `0x99` 替换为真浏览器的 `0x99` | **`HTTP 200 OK`** | **决定性突破**：本地 Node VM 生成的 Prelude 与末尾 288B 内容绑定签名块 **100% 被 Google 服务端接受**！唯一的 403 根因就在 `0x99` 遥测段的明文内容中！ |

### 4.2 破解 `0x99` 段的 CFB 流密码并逐块对比明文

通过逆向 `ul`（`inner.cizw.js`）中的加密逻辑，我们还原了 `0x99` 段（`reg 291` / `reg 179`）的加密方式：
- 并非固定密钥流 XOR，而是**密文反馈模式（CFB，8 字节分组）**：
  - 初始 8 字节由 `k5` 生成随机 IV（不依赖密钥）。
  - 第 $N$ 个 8 字节块（$N \ge 1$，偏移 $Z_2 = 8N$）的密钥流 `I7` 由**前一个 8 字节密文块**（偏移 $Z = 8N - 8$，拆为两个 32-bit 整数 `gp(cipher, Z+4)` 与 `gp(cipher, Z)`）作为输入，调用 14 轮 ARX 函数 `Oj` 生成：
    $$\text{Keystream}_N = \text{Oj}\big(29,\ \text{u32}(C, 8N-4),\ 1770,\ [0, 0, T_1, T_2],\ \text{u32}(C, 8N-8)\big)$$
    其中常数密钥 $T_1 = -1290220787$，$T_2 = -923460489$（存储在 `reg 155`）。
- 由于每个 8 字节块的密钥流仅依赖前一个 8 字节密文块，我们可以：
  1. 编写 `decryptCFB()` 将真浏览器与本地 Node VM 的 `0x99` 段**完整解密为明文 TLV 字节流**；
  2. 在 `oracle_99_chunks.js` 中对明文块做二分替换后**重新 CFB 加密**提交给服务端，从而以单字节精度定位服务端校验的每一个 Tag！

---

## 5. `0x99` 遥测段的四大校验点与完整伪装方案

通过对比真浏览器与本地 Node VM 的 `0x99` 明文写入序列（约 420 次 `ul`/`XX` 调用），并结合跨版本 Challenge（`cizw` / `Qoo_` / `yoc_`）测试，我们找出了服务端校验的全部 4 类核心遥测记录：

### 5.1 校验点一：6 路动态 `typeof` 环境探针（Tag `3` + Re-key + Tag `103`）

每个 `Waa/Create` Challenge 会随机抽取 6 个环境属性测试 `typeof`：
- **前 3 个探针**：带 6 字节随机盐拼接后写入 Tag `3`，并送入 `GX` 重设字节码流密码密钥。
- **后 3 个探针**：带 6 字节随机盐拼接后**不参与 Re-key**，而是经 `JU` 哈希成 4 字节直接写入 **Tag `103`**！
  - 这非常狡猾：如果后 3 个探针中有某个属性在沙箱中是 `"undefined"`，字节码**不会崩溃**，依然能产出看似正常的 `V` 证明，但 Tag `103` 的 4 字节哈希值不对，服务端直接判 `403`！
- **实测遇到的动态探针样例**：
  - `cizw`：`window.RTCStatsReport`、`div.style.marginRight`、`window.XRProjectionLayer`、`img.removeChild`、`MouseEvents.screenX`、`img.scrollTop`
  - `Qoo_`：`window.CloseWatcher`、`div.style.timelineTriggerActiveRange`、`navigator.leaveAdInterestGroup`、`MouseEvents.pageX`、`img.offsetWidth`、`img.DOCUMENT_POSITION_CONTAINED_BY`
  - `yoc_`（样本 1）：`window.CSSPositionValue`、`div.style.interpolateSize`、`window.crashReport`、`img.offsetHeight`、`img.insertBefore`、`MouseEvents.bubbles`
  - `yoc_`（样本 2）：`window.WindowControlsOverlayGeometryChangeEvent`、`window.when`（继承自 `EventTarget.prototype`！）、`div.style.lineBreak`、`MouseEvents.eventPhase`、`img.replaceChild`、`img.hasAttributeNS`

**修复方案**：
通过 CDP 从真实 Chrome 151 提取完整对象及原型链上的 `typeof` 字典写入 `src/browser/chrome-schema.json`：
- `winProps`（1,231 项，包含 `window` 自有属性及继承自 `Window.prototype` $\rightarrow$ `EventTarget.prototype` 的 `when`、`TEMPORARY`、`PERSISTENT`、`crashReport` 等小写属性）
- `styleTypes`（754 项 `CSSStyleDeclaration` 属性）
- `imgTypes`（375 项）、`divTypes`（346 项）、`docTypes`（302 项）、`navTypes`（79 项 `Navigator.prototype` 属性/方法）、`mouseEvTypes`（53 项）、`screenTypes`（15 项）、`perfTypes`（22 项）
在 `src/browser/env.js` 初始化时全量挂载，确保任意随机组合的 6 路探针 100% 返回与 Chrome 151 完全一致的 `typeof` 字符串。

---

### 5.2 校验点二：`iframe.contentWindow` 构造器 `.prototype` 抽样（Tag `232` & Tag `233`）

在创建 `bscframe` iframe 后，VM 会在 `iframe.contentWindow`（即沙箱中的 `childWindow`）上执行两组原型抽样：
1. **Tag `232`**：随机抽取 1~2 个构造器，检查 `Object.getOwnPropertyNames(childWindow[Ctor].prototype)` 的属性个数及指定下标的属性名哈希。
2. **Tag `233`**：固定抽取 **9 个构造器**，对每个构造器读取：
   $$\text{propName} = \text{Object.getOwnPropertyNames}(\text{childWindow}[\text{Ctor}].\text{prototype})[\text{idx}]$$
   并将 `[CtorHash(4B), idx(2B), JU(propName)(4B)]` 写入 `0x99` 的 Tag `233`。

**踩坑与修复**：
- **坑 1（ECMAScript 内建构造器漏挂）**：某个 `Qoo_` Challenge 抽到了 `childWindow.WeakMap`（读取 `idx = 1` 即 `"delete"`），而最初 `childWindow` 只挂载了 `Object/Array/String/Number/...` 等 11 个基础构造器，未挂载 `WeakMap/Map/Set/Symbol/ArrayBuffer` 等，导致 `childWindow.WeakMap` 为 `undefined`。
- **坑 2（DOM 子类原型属性缺失与顺序错位）**：某个 `yoc_` Challenge 抽到了 `childWindow.HTMLAnchorElement`，而手写的 `HTMLAnchorElement.prototype` 只有 `['constructor', 'hrefTranslate']` 2 个属性（真实 Chrome 151 有 29 个属性且按 WebIDL 顺序排列，`constructor` 在末尾而非开头）。
- **修复方案**：
  - 将全部 `JS_CORE_BUILTINS` 与 `CHROME_SCHEMA.winProps` 中的 1,228 个构造器（含每个构造器的精确 `proto` 属性名列表）注入 `childWindow`。
  - 实现 `makeElementSubProto()`：对 `HTMLAnchorElement`、`HTMLMediaElement`、`HTMLIFrameElement`、`Navigator`，先严格按照 Chrome 151 的 `proto` 数组顺序定义属性（保证 `Object.getOwnPropertyNames` 顺序 100% 一致），再就地 `Object.defineProperty` 绑定具体 getter/method；若某属性（如 `src`、`contentWindow`、`contentDocument`）在父类 `DOMElement.prototype` 上已有访问器，则直接复用其 descriptor，防止 `value: undefined` 遮蔽父类功能。

---

### 5.3 校验点三：WebIDL 原型链与 Iframe 生命周期反篡改位图（Tag `[250, 18]`）

在 `0x99` 明文末尾附近，VM 写入一条 6 字节记录：`[250, 18, b0, b1, b2, b3]`（32-bit 反篡改位图）。
- 真浏览器中该记录恒为 **`[250, 18, 0, 4, 0, 0]`**（整数值 `0x00040000 = 262144`）。
- 修复前本地沙箱该记录为 **`[250, 18, 16, 45, 76, 84]`**（十余个篡改检测位被触发置 1）。

通过逐条追踪位图置位指令（`cizw` 的 `pc = 16000..17628`），还原出其检测逻辑：
1. **WebIDL 属性描述符检测**：使用 `Object.getOwnPropertyDescriptor` 检查：
   - `Navigator.prototype` 上的 `plugins`、`mimeTypes`、`webdriver`
   - `HTMLIFrameElement.prototype` 上的 `srcdoc`、`contentWindow`
   - `HTMLAnchorElement.prototype` 上的 `hrefTranslate`
   - `HTMLMediaElement.prototype` 上的 `canPlayType`
   检测条件包括：
   - 实例自身不能有同名自有属性（`Object.prototype.hasOwnProperty.call(navigator, 'webdriver')` 必须为 `false`）；
   - Descriptor 必须具有 `get` 函数，且 `get.name === 'get <prop>'`；
   - `get.toString()` 必须匹配 `/\[native code\]/`；
   - **非法调用检测（Illegal Invocation）**：直接调用 ` desc.get.call({})` 或 `HTMLAnchorElement.prototype.hrefTranslate` 必须抛出 `TypeError("Illegal invocation")`！
2. **Iframe 挂载生命周期检测**：
   - `const ifr = document.createElement('iframe')` 尚未 `appendChild` 时，`ifr.contentWindow` 必须为 `null`；
   - `body.appendChild(ifr)` 后，`ifr.contentWindow === ifr.contentWindow` 必须引用恒等且非空；
   - `body.removeChild(ifr)` 后，`ifr.contentWindow` 必须恢复为 `null`。

在 `src/browser/env.js` 中按上述规范实现 `makeNativeGetter`、`makeNativeSetter`、`makeNativeMethod` 及 `DOMElement.prototype.contentWindow` 后，本地沙箱的 Tag `[250, 18]` 精确归零为 **`[250, 18, 0, 4, 0, 0]`**。

---

### 5.4 校验点四：32 桶 DOM 用户交互事件直方图（Tag `235`）

当上述三项全部对齐后，对比真浏览器与本地 `0x99` 的最后 3 个块（Chunk 115~117），并通过 `oracle_99_chunks.js` 逐块替换发现：
- 仅替换 Chunk 115~116（对应 **Tag `235`**，16 字节：`[235, hi4B, lo4B, count4B, b1, b2, b3]`）即可决定 `200 OK` 与 `403`！
- 追踪写入 Tag `235` 的指令（`pc = 23485`）发现，它汇总了初始化期间注册在 `document` / `document.body` 上的 **32 桶 DOM 事件监听器（`reg 191`）** 的触发计数与时间戳差值。
- 在纯 Node 沙箱中，由于没有任何鼠标或键盘事件发生，Tag `235` 恒为全零：
  `[235, 0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0]`，被服务端直接识别为无交互自动化环境并拒绝（`403`）。

**修复方案（`src/waa/service.js` -> `simulateUserInteraction()`）**：
在 `WaaService.init()`（VM 注册回调后）以及 `beforeMint()`（每次 `snapshot` 前），向 `document` 与 `document.body` 派发合成交互事件序列（`mousemove` $\rightarrow$ `mousedown` $\rightarrow$ `mouseup` $\rightarrow$ `click` $\rightarrow$ `keydown` $\rightarrow$ `keyup` $\rightarrow$ `focus`），携带递增的 `timeStamp` 与坐标偏移。
派发后 Tag `235` 变为非零活跃直方图（如 `[235, 0,0,0,0, 0,0,5,212, 0,0,0,1, 0,0,0]`），`GenerateContent` 立即返回 **`HTTP 200 OK`**！

---

## 6. 最终验证结果

### 6.1 连续动态 Challenge 端到端测试（`--proof node-vm`）

在完全移除静态 Proof 与 Challenge 缓存的情况下，每次调用均由 Node.js 实时请求 `Waa/Create` 获取新 Challenge（覆盖 Google 随机下发的 `Qoo_` 与 `yoc_` 两个不同 VM 家族），在 `node:vm` 内铸造 Proof 并请求 `GenerateContent`：

| 轮次 | `Waa/Create` 下发程序 | 冷启动耗时 | Proof 长度 / 模式 | `GenerateContent` 状态 | 模型返回结果 |
|---|---|---|---|---|---|
| 1 | `Qoo_` (`cIZw7Fa...`) | `1424 ms` | `1551 chars` / `V` (`S=100`) | **`HTTP 200 OK`** | `30` (`5*6`) |
| 2 | `Qoo_` (`cIZw7Fa...`) | `1174 ms` | `1547 chars` / `V` (`S=100`) | **`HTTP 200 OK`** | `15` (`7+8`) |
| 3 | `Qoo_` (`cIZw7Fa...`) | `1494 ms` | `1556 chars` / `V` (`S=100`) | **`HTTP 200 OK`** | `81` (`9*9`) |
| 4 | `Qoo_` (`cIZw7Fa...`) | `1038 ms` | `1549 chars` / `V` (`S=100`) | **`HTTP 200 OK`** | `63` (`100-37`) |
| 5 | `Qoo_` (`cIZw7Fa...`) | `1314 ms` | `1540 chars` / `V` (`S=100`) | **`HTTP 200 OK`** | `144` (`12*12`) |
| 6 | `yoc_` (`C7AoLbL...`) | `1180 ms` | `1552 chars` / `V` (`S=100`) | **`HTTP 200 OK`** | `30` (`5*6`) |

### 6.2 常驻热态连续 Mint 基准测试

在单个常驻 `Runtime` 实例（`provider=node-vm`）中连续执行多次 `snapshot` + `generate`：
- **第 1 次热态 Mint**：`37 ms`（`proofLen = 1588`，`HTTP 200 OK`）
- **第 2 次热态 Mint**：`27 ms`（`proofLen = 1595`，`HTTP 200 OK`）
- **第 3 次热态 Mint**：`41 ms`（`proofLen = 1595`，`HTTP 200 OK`）
- **进程总内存占用**：`RSS = 135.5 MB`，`heapUsed = 35.9 MB`。

---

## 7. 核心改动文件索引

1. `/root/waavm-ref/waa-runtime/src/browser/chrome-schema.json`
   - 从 Chrome 151 导出的完整属性类型与原型表（`winProps`、`imgTypes`、`divTypes`、`styleTypes`、`mouseEvTypes`、`navTypes`、`docTypes`、`screenTypes`、`perfTypes`、`histTypes`、`locTypes`）。
2. `/root/waavm-ref/waa-runtime/src/browser/env.js`
   - 注入 `CHROME_SCHEMA` 全量属性类型与构造器原型；
   - 实现 `makeElementSubProto()`、`makeNativeGetter()`、`makeNativeSetter()`、`makeNativeMethod()` 满足 WebIDL 原型链顺序与非法调用反篡改检查；
   - 补齐 `childWindow`（`iframe.contentWindow`）的 `JS_CORE_BUILTINS` 与 DOM 挂载生命周期。
3. `/root/waavm-ref/waa-runtime/src/waa/service.js`
   - 新增 `simulateUserInteraction()`，在初始化及每次 `snapshot` 前派发合成 DOM 交互事件填充 `0x99` Tag `235` 直方图。
