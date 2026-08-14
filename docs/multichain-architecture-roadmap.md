# Multichain Architecture Roadmap

本文档记录当前 Jade/T-Display-S3 多链固件的架构审视和后续重构计划。它不是一次性大重构方案，而是一个小步演进路线：每一步都必须保持可编译、可测试、可刷机调试，并且不能放松私钥、助记词、seed、xpriv 的安全边界。

## 设计原则

- 安全优先。协议层、链层、UI 层不得读取 seed、mnemonic、xpriv、raw private key，也不得返回可还原私钥的中间态。
- USB 主机不可信。所有 Trezor protobuf、wire、TxAck、EthereumTxAck、definitions、calldata 都按恶意输入处理。
- 统一签名边界。链代码负责解析、校验、生成 digest；`wallet_core` 负责在内部派生私钥并签名；协议层只负责请求/响应格式。
- 小步重构。每次只拆一块，先加门禁，后迁移调用，再删旧代码。
- 兼容 Jade 工程约束。新增 `.c` 文件要同时考虑 ESP-IDF `SRC_DIRS`、host gate 手工源列表、`main/amalgamated.c`。
- 兼容 T-Display-S3 硬件约束。交易确认摘要必须符合现有 LCD 行数、按键导航、Activity 生命周期和 FreeRTOS 栈限制。
- 协议规范优先级：链官方规范和 BIP/EIP/TRON 文档 > Trezor official common/protob / Connect 行为 > OneKey 实践参考。
- OneKey 只作架构和流程参考，不直接复制实现，尤其不能引入 OneKey 私有 proto 扩展来假装 Trezor/MetaMask 兼容。

## 当前代码现状

已经比较清楚的边界：

- `main/wallet_core/`
  - 已成为新增多链路径的密钥边界。
  - `wallet_core_sign_digest_ecdsa_recoverable()` 是当前多链 ECDSA digest 签名入口。
  - 已有 `tools/check_sensitive_key_boundaries.py` 防止 `main/chains` 和 `main/protocols/trezor` 直接触碰私钥/seed/mnemonic/keychain private derivation。

- `main/chains/`
  - ETH 已有较完整的 `tx`、`digest`、`authorize`、`confirm`、`wallet` 分层。
  - TRON 已有 `address`、`tx`、`authorize`、`confirm`、`wallet` 基础层，但 USB/Trezor path 尚未正式开放。
  - BTC 已有 address/path/wallet/confirm，并且 Trezor P2WPKH SignTx 已可用。

- `main/protocols/trezor/`
  - 已有 WebUSB/HID transport、wire、protobuf、session、features、public key、ETH、BTC 基础协议。
  - BTC `prev_tx_verifier` 已从 `bitcoin/protocol.c` 拆到独立模块，并已接入
    `signing_state` 的 prev_tx collect/verify 子流程。
  - ETH 有 `ethereum/normalizer.c`，BTC 还没有正式 normalizer。

主要问题：

- `main/protocols/trezor/session.c` 仍然承担太多职责：message routing、本机解锁挂起、ETH signing continuation、BTC signing continuation、failure 语义、ButtonAck/TxAck 状态推进都在里面。
- `main/protocols/trezor/wallet_adapter.c` 混合了地址派生、public key/xpub、ETH 签名、BTC UI 确认、BTC digest 签名、wallet ready 判断。
- `main/protocols/trezor/bitcoin/protocol.c` 仍然偏大，里面还有 protobuf decode、TxRequest encode、SignTx 状态机、P2WPKH policy、signed tx encode 等不同职责。
- 还没有正式的 Request Normalizer 层。ETH 有一个最小 normalizer，BTC/TRON 还没有统一形态。
- 还没有统一的 Internal Chain Request / Review Model 边界。现在 ETH/BTC/TRON 各自有 confirm request，但协议层到链层的抽象不一致。
- host gate 功能强，但 `main/test/eth_tron_address_gate.c` 已经很大，后续需要按链和协议拆分。
- Trezor protobuf 是手写最小 subset。短期利于攻击面控制，长期需要 schema 对照门禁，避免字段号、enum、wire format 漂移。

## OneKey 值得参考的实践

OneKey 的价值主要在目录组织和 signing flow 拆分，而不是可直接复制的代码。

高价值参考：

- `common/protob/messages-bitcoin.proto`
- `common/protob/messages-ethereum.proto`
- `common/protob/messages-tron.proto`
- `core/src/apps/bitcoin/sign_tx/bitcoin.py`
- `core/src/apps/bitcoin/sign_tx/helpers.py`
- `core/src/apps/bitcoin/sign_tx/approvers.py`
- `core/src/apps/bitcoin/sign_tx/tx_info.py`
- `core/src/apps/bitcoin/sign_tx/sig_hasher.py`
- `core/src/apps/ethereum/sign_tx.py`
- `core/src/apps/ethereum/sign_tx_eip1559.py`
- `core/src/apps/ethereum/definitions.py`
- `core/src/apps/ethereum/layout.py`
- `core/src/apps/tron/sign_tx.py`
- `core/src/apps/tron/serialize.py`
- `core/src/apps/tron/tokens.py`

可吸收的架构思想：

- Bitcoin signing 分阶段：
  - process inputs
  - approve outputs
  - approve fee/locktime/total
  - verify prev_tx
  - serialize inputs
  - serialize outputs
  - sign segwit/non-segwit
  - finish transaction
- BTC `Approver` 单独负责金额、找零、fee、payment request、original tx/replacement 等策略。
- BTC `helpers` 单独负责 request/ack 流程，不把协议 request 构造散落到 signing 逻辑里。
- BTC `tx_info` 单独维护 transaction check digest / original transaction hash state。
- ETH 把 ERC20/token definitions/layout/signing digest 分开。
- TRON 把 serialize、tokens、layout、sign_tx 分开。

不能照搬的地方：

- OneKey 多数核心是 Python/MicroPython 风格，我们是 ESP-IDF/C/Jade 原工程。
- OneKey 有自己的 proto 扩展，如 `messages-ethereum-onekey.proto`，不能作为 Trezor Connect/MetaMask 兼容主依据。
- OneKey signing 代码里有直接拿私钥的实现形态。我们不能让链层拿 raw private key，必须坚持 `wallet_core sign_digest` 边界。

## 目标架构

长期目标调用链：

```text
Transport
  -> Protocol Adapter
  -> Request Normalizer
  -> Chain Core / Policy
  -> Review Model
  -> UI Confirm
  -> Wallet Core sign_digest
  -> Protocol Response Encoder
```

目标目录形态以当前工程为基础小步演进：

```text
main/
  protocols/
    trezor/
      transport/              # long-term split from usb_hid.c/wire.c
      protobuf/               # current protobuf.c/h, maybe schema gates later
      session.c               # protocol session only
      app_service.c           # dispatch into chain services
      bitcoin/
        messages.c/h          # SignTx/TxAck/GetAddress protobuf subset
        requests.c/h          # TxRequest encode/decode helpers
        signing_state.c/h     # SignTx state machine
        normalizer.c/h        # Trezor state -> internal BTC request
        policy.c/h            # P2WPKH, fee, change, prev_tx policy
        prev_tx_verifier.c/h  # already split
      ethereum/
        protocol.c/h
        normalizer.c/h
        definitions.c/h
      tron/
        protocol.c/h
        normalizer.c/h
  chains/
    bitcoin/
      address.c/h
      path.c/h
      wallet.c/h
      tx_plan.c/h             # future normalized BTC transaction plan
      confirm.c/h
      signer.c/h              # uses wallet_core only through digest signing
    ethereum/
      tx_request.c/h
      authorize.c/h
      digest.c/h
      confirm.c/h
      sign.c/h
    tron/
      tx.c/h
      authorize.c/h
      confirm.c/h
      signer.c/h
  ui/
    chain_confirm.c/h
  wallet_core/
    wallet_core.c/h
```

## 分阶段重构计划

### Phase 0: 守住安全边界

已完成：

- 敏感接口静态门禁：`tools/check_sensitive_key_boundaries.py`。
- ETH/BTC/TRON 地址、签名、protobuf、UI 摘要、外部 oracle host gates。
- BTC P2WPKH/BIP84 硬件协议测试。

继续要求：

- 每次新增链层/协议层文件，都必须被 sensitive key boundary gate 覆盖。
- 新增 signer 只能调用 `wallet_core_sign_digest_ecdsa_recoverable()` 或未来统一 signer API。
- 不允许新增 `get_private_key()`、`wallet_get_hdkey(... PRIVATE ...)` 到链层/协议层。

### Phase 1: 拆 BTC 协议层大文件

目标：把 `main/protocols/trezor/bitcoin/protocol.c` 拆成 OneKey 风格的职责模块，但每一步只迁一类逻辑。

已完成：

- `prev_tx_verifier.c/h` 已独立。
- `policy.c/h` 已独立，集中 P2WPKH-only、fee-rate、change path、single external output、lock_time/serialize 等当前签名策略。
- `requests.c/h` 已独立，集中 Trezor `TxRequest`、prev_tx `tx_hash` request、多输入 signed response 编码。
- `signing_state.c/h` 已独立，集中 `SignTx -> TxAck -> ready` 状态推进，并显式区分
  current transaction `TXMETA/TXINPUT/TXOUTPUT` 与 prev_tx
  `TXMETA/TXORIGINPUT/TXORIGOUTPUT` 状态。
- `messages.c/h` 已独立，集中 BTC Trezor protobuf decode/encode，包括 `GetAddress`、`SignTx`、`TxAck`、prev input/output、Address response。

下一步建议顺序：

1. `bitcoin/normalizer.c/h`
   - 把 Trezor signing state 转成内部 BTC review/sign request。
   - 为 legacy/P2SH 后续开放做准备。

2. `bitcoin/signing_state.c/h` 后续完善
   - 已有 prev_tx request/ack collect/verify host harness。
   - 已补 scriptPubKey 与派生路径/脚本类型绑定。下一步在真实签名 oracle 建好后，
     再考虑开放 P2SH-P2WPKH 签名。

门禁：

- `tools/run_host_gates.sh build-tdisplays3-hardened-ok`
- `tools/run_btc_hardware_protocol_tests.py`
- full ESP-IDF build
- sensitive key boundary gate

### Phase 2: BTC prev_tx 接入 SignTx 状态机

目标：当遇到 legacy/P2SH-P2WPKH 输入时，不再只是拒绝，而是先走 prev_tx verification，再决定是否允许进入签名。

步骤：

1. 只设计 host harness，不碰硬件签名。已完成基础版本：
   - 构造 `SignTx -> current TXINPUT -> current TXOUTPUT -> prev TXMETA -> prev inputs -> prev outputs` 的官方 Trezor flow。
   - 使用 `trezorlib` 驱动协议行为。
   - 验证 legacy/P2SH-P2WPKH 会请求 prev_tx、校验 txid/prevout amount 后仍按当前策略拒绝签名。
   - 已签名的 P2WPKH raw tx 继续使用 `embit` 独立验证。

2. 接入 `prev_tx_verifier` 到 BTC signing state。基础版本已完成：
   - 当前 input.prev_hash 必须等于 verifier 重算 TXID。
   - 当前 input.prev_index 必须从 verified prevout 取 amount/script_pubkey。
   - 对 legacy/P2SH，禁止继续信任主机在 current input 里给的 amount。

3. 接入 `script_policy` 到 prev_tx finish 流程。已完成基础版本：
   - P2PKH：`address_n/script_type` 必须生成与 verified prevout 相同的
     `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`。
   - P2WPKH：支持标准 `0 <pubKeyHash>` 模板校验。
   - P2SH-P2WPKH：必须先由 `address_n` 生成 `0 <pubKeyHash>` redeem script，
     再 hash160 后匹配 verified prevout 的 `OP_HASH160 <redeemHash> OP_EQUAL`。
   - 超长、未知、非标准、路径不匹配脚本全部拒绝。
   - Host oracle 使用 `embit.script` 生成脚本向量，避免本仓 C 代码自测自己。

仍未完成：

- legacy P2PKH non-segwit sighash / scriptSig 序列化。
- P2SH-P2WPKH signed raw tx 独立 oracle 和硬件 trezorlib 测试。
- legacy/P2PKH signed raw tx 独立 oracle 和硬件 trezorlib 测试。
- Host gate 目前 BTC 签名仍使用 fake signature，只能验证 raw tx 结构；开放
  legacy/P2SH 签名前必须增加真实签名/digest oracle。

4. P2SH-P2WPKH 优先于 legacy P2PKH。
   - P2SH-P2WPKH 可以继续使用 segwit v0 sighash，但 prevout script/redeem script 绑定更严格。
   - legacy P2PKH 需要 non-segwit sighash 和 scriptSig 序列化，风险更高，排在后面。

5. legacy P2PKH 后续再开放。
   - 必须有 prev_tx verified amount/script。
   - 必须有 signer digest oracle。
   - 必须有 raw tx oracle。

暂不做：

- multisig
- PSBT
- Taproot
- external input / payjoin / replacement tx

### Phase 3: 收敛 Protocol Adapter / App Service

目标：让 USB/session 不再直接持有一堆业务 callback。

当前问题：

- `trezor_session_t` 里有 `get_bitcoin_address`、`get_eth_address`、`get_public_key`、`sign_eth_tx`、`confirm_btc_tx`、`sign_btc_digest`。
- 新增 TRON/Ledger/Jade RPC 时 callback 会持续膨胀。

目标接口：

```c
typedef enum {
    APP_REQUEST_GET_ADDRESS,
    APP_REQUEST_GET_PUBLIC_KEY,
    APP_REQUEST_SIGN_TX,
    APP_REQUEST_SIGN_MESSAGE,
} app_request_type_t;

typedef struct {
    app_request_type_t type;
    chain_id_t chain;
    const void* request;
} app_request_t;

typedef struct {
    uint16_t protocol_response_type;
    uint8_t* payload;
    size_t payload_len;
} app_response_t;
```

小步实现：

1. 新增 `protocols/trezor/app_service.c/h`，先包装现有 callback。
2. session 只调用 app_service，不直接调用 wallet_adapter 的链业务函数。
3. wallet_adapter 再拆成：
   - address service
   - public key service
   - signing service
   - UI review service

### Phase 4: 统一 Review Model

目标：所有链都先生成 `chain_confirm_summary_t` 或更强的 typed review model，再调用 UI。

当前已有：

- `main/chains/confirm_summary.c/h`
- `main/ui/chain_confirm.c/h`
- ETH/BTC/TRON confirm summary gates

需要补强：

- 每个签名请求都必须有 “review model -> digest binding” 门禁。
- UI 页面行数、分页、back/cancel、final confirm 行为必须做 host gate。
- 签名成功后的状态切换必须统一：短暂 Signed/Sent to host，再回 Dashboard/Unlock。

OneKey 参考：

- ETH `layout.py`
- BTC `sign_tx/layout.py`
- TRON `layout.py`

Jade 约束：

- 不能直接套 OneKey UI。
- 必须适配 T-Display-S3 行数、双按键、`navbtns.inc`、Activity 生命周期。

### Phase 5: ETH/TRON 架构收敛

ETH 当前已经比较接近目标，但仍可继续拆：

- `protocols/trezor/ethereum/protocol.c`
  - 保留 protobuf decode/encode。
- `protocols/trezor/ethereum/normalizer.c`
  - 保留 Trezor signing state -> `ethereum_tx_preflight_request_t`。
- `chains/ethereum/authorize.c`
  - 负责 ERC20/unknown contract/policy。
- `chains/ethereum/digest.c`
  - 负责 legacy/EIP1559 signing digest。
- `chains/ethereum/sign.c`
  - 只调用 wallet_core signer。

TRON 需要补：

- Trezor/OneKey compatible protobuf subset。
- TRON raw transaction serialize/digest oracle。
- TRC20 transfer/approve summary and token metadata gates。
- TRON signer 必须走 wallet_core digest signer，不按 OneKey 方式把 seckey 暴露给链层。

### Phase 6: 测试体系拆分

当前问题：

- `main/test/eth_tron_address_gate.c` 过大。
- `tools/run_external_oracle_gates.py` 过大。

目标拆分：

```text
main/test/
  btc_protocol_gate.c
  btc_policy_gate.c
  eth_gate.c
  tron_gate.c
  ui_confirm_gate.c
  wallet_core_public_node_gate.c

tools/
  oracle_eth.py
  oracle_btc.py
  oracle_tron.py
  run_external_oracle_gates.py
  run_btc_hardware_protocol_tests.py
```

要求：

- 独立 oracle 不能用本工程代码验证本工程结果。
- ETH 使用 `eth-utils`、`rlp`、`eth-keys`。
- BTC 使用 `trezorlib`、`embit` 或等价社区库。
- TRON 使用官方/社区 Base58Check、protobuf/tx serialize 对照。
- USB/protobuf malformed 输入必须持续覆盖。
- 签名前后关键资金字段尽量做 host oracle 门禁：BTC raw tx 的 from witness pubkey、to script、amount、change script、fee、sighash、签名有效性都应由 `embit`/`trezorlib` 比对。硬件测试只补真实 USB transport、设备确认 UI、真实签名路径和主机占用/超时类问题。

## 短期优先队列

建议接下来按这个顺序推进：

1. BTC 真实签名/digest oracle
   - 当前 host gate 的 BTC wallet 签名是 fake signature，不能证明 ECDSA 有效。
   - 需要建立不泄漏固件私钥的本机 oracle：用第三方库对同一 digest/交易语义签名或验签。

2. P2SH-P2WPKH 签名实验性接入
   - 只在 prev_tx verified 后允许。
   - 必须有 host oracle 和硬件 trezorlib 测试。

3. legacy P2PKH 签名设计
   - 先做 non-segwit sighash/raw tx oracle。
   - 再考虑硬件签名入口。

## 每次改动必须检查

- 是否新增了链层/协议层访问私钥、seed、mnemonic、xpriv 的可能。
- 是否绕过了本机 UI 确认。
- 是否让 USB malformed input 可以造成越界、溢出、无限循环、FreeRTOS 卡死、重启。
- 是否影响 `main/amalgamated.c`。
- 是否影响 host gate 手工源文件列表。
- 是否影响 T-Display-S3 屏幕行数和双按键确认流程。
- 是否保持 Secure Boot / Flash Encryption 关闭。
- 是否有第三方/官方 oracle 验证关键资金安全结果。

## 当前明确不做

- 不引入 Python/MicroPython 到固件运行时。
- 不直接导入 OneKey 私有 proto 扩展作为 MetaMask/Trezor Connect 主协议。
- 不开放 legacy/P2SH/multisig/PSBT，直到 prev_tx verification、script policy、UI 摘要和 raw tx oracle 都完成。
- 不让 Ledger APDU 影响 chain core。Ledger 只能作为 adapter。
- 不让 USB 层直接调用 wallet_core signer；最终必须经 app service / chain policy / UI review。
