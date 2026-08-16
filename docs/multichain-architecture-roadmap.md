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
- OneKey 只作架构和流程参考，不直接复制实现。OneKey 私有 proto 扩展必须放在
  单独 adapter/feature gate 下，不能假装成 Trezor/MetaMask 标准兼容。

## 当前代码现状

已经比较清楚的边界：

- `main/wallet_core/`
  - 已成为新增多链路径的密钥边界。
  - `wallet_core_sign_digest_ecdsa_recoverable()` 是当前多链 ECDSA digest 签名入口。
  - 已有 `tools/check_sensitive_key_boundaries.py` 防止 `main/chains` 和 `main/protocols/trezor` 直接触碰私钥/seed/mnemonic/keychain private derivation。

- `main/chains/`
  - ETH 已有较完整的 `tx`、`digest`、`authorize`、`confirm`、`wallet` 分层。
  - TRON 已有 `address`、`tx`、`authorize`、`confirm`、`wallet` 基础层，但 USB/Trezor path 尚未正式开放。
  - BTC 已有 address/path/wallet/confirm。Trezor-compatible `SignTx` 已支持
    BIP84/P2WPKH，并实验性支持 BIP44/P2PKH、BIP49/P2SH-P2WPKH。

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
- BTC legacy/P2PKH 与 P2SH-P2WPKH 的真实硬件 trezorlib 测试入口已补到
  `tools/run_btc_hardware_protocol_tests.py --include-legacy`，但仍需在设备解锁后
  跑实测确认 USB transport、UI 确认和真实 `wallet_core` 签名路径。
- OneKey `SignPsbt` 消息号已登记到 trace，并在 session 层明确返回 DataError；
  当前不解析 PSBT payload，不触碰 signer。
- BTC `GetPublicKey` 已支持账户级 BIP44/P2PKH、BIP49/P2SH-P2WPKH、BIP84/P2WPKH，
  覆盖 Bitcoin/Testnet，并按 Trezor/OneKey 的 `script_type + ignore_xpub_magic` 规则选择
  `xpub/tpub/ypub/upub/zpub/vpub` 公钥版本字节。
- BTC `GetPublicKey` 已支持多签 xpub-only 导入路径：
  BIP45 `m/45'` 返回 `xpub/tpub`，BIP48 `m/48'/coin'/account'/1'` 返回
  `Ypub/Upub`，BIP48 `m/48'/coin'/account'/2'` 返回 `Zpub/Vpub`。这只表示
  Sparrow/OneKey 可以获取 cosigner public node；真实签名只开放受限 partial-signing，
  设备不组合完整多签交易。
- BTC `GetAddress.multisig` 已开放 P2SH、P2WSH、P2SH-P2WSH 三种 Trezor
  multisig 地址请求。实现遵循 OneKey/Trezor 的安全原则：先把
  `MultisigRedeemScriptType` 归一化成内部 policy/redeem script/scriptPubKey，
  再派生本机公钥并确认它属于该 policy，最后才返回/展示地址。若 policy 不包含
  本机公钥，地址请求会拒绝。
- BTC 多签签名前置 gate 已补齐核心路径：`script_policy` 能验证 `TxInput.multisig`
  的轻量 summary scriptPubKey 与 prev_tx verifier 返回的 prevout scriptPubKey 是否一致，
  并检查 Trezor `script_type` 与内部 `MULTI_P2SH/MULTI_P2WSH/MULTI_P2WSH_P2SH`
  variant 是否匹配。这是进入受限 partial-signing 之前的资金安全门禁。
- BTC `MultisigRedeemScriptType` normalizer 已生成 OneKey/Trezor 风格 policy fingerprint
  并有 host gate 覆盖。fingerprint 目前只存在完整 policy/normalizer 层，不进入
  `TxInputType`/`TxOutputType` 的长期 summary，避免扩大 signing state 内存面。
- BTC 多签 policy fingerprint matcher 已作为独立策略原语落地，语义参考 OneKey
  `MultisigFingerprintChecker`：所有内部 input 的 fingerprint 一致时，匹配同一
  fingerprint 的 output 才可作为找零；一旦 input fingerprint 混合或缺失，就禁止
  多签找零识别。matcher 带 `read_only` 防护，开始判断 output 后不能再追加 input。
  `TxAck` 解码器现在可以通过旁路结构返回 input/output 的 multisig fingerprint，
  `signing_state` 会保存这些 32 字节摘要；它不保存完整 multisig policy、xpub
  或 redeem script，避免扩大长期状态里的攻击面。
- BTC `MultisigRedeemScriptType` 现在可以归一化为内部 descriptor 摘要：variant、
  threshold、signer count、排序模式、shared path、policy fingerprint、redeem/scriptPubKey
  长度，以及“本机派生公钥是否属于该 policy”。该 descriptor 不保存 xpub、完整
  redeem script、signature 或私钥材料；host oracle 用 embit 构造脚本并校验这些
  字段，作为后续 UI/签名前的 policy 绑定门禁。
- BTC 策略层已有 `trezor_bitcoin_policy_multisig_output_matches_inputs()` 原语，
  用保存的 fingerprint 判断某个 multisig output 是否与所有 multisig inputs
  属于同一 policy。当前实现故意保守：混合 singlesig/multisig、缺 fingerprint、
  input fingerprint 不一致、output fingerprint 不匹配都会返回 false。
- BTC 多签 preview/confirm plan 已有第一版门禁：所有 inputs 必须是多签、必须有
  verified prevout script 和 fingerprint；外部 output 必须是 address，找零 output
  必须是同 policy multisig；所有 input 还必须使用相同钱包路径前缀和脚本 variant，
  change 必须与 input 绑定到同一 BIP45/BIP48 钱包前缀，并使用分支 1。当前只允许一个外部付款输出，以适配现有
  `bitcoin_confirm_request_t` UI 摘要结构。该路径会先生成确认摘要，确认后才进入
  partial-signing digest 构造。
- BTC 多签 `SignTx` 状态机现在把任何 multisig input 都纳入 prev_tx 验证流程。
  只有 prevout scriptPubKey 与 multisig policy 绑定通过后，才会生成 UI preview。
  UI 摘要会显示非敏感 `Policy` 文本，例如 `2-of-3 P2WSH`。用户确认后只返回本机
  cosigner 对每个 input 的 partial signature，不返回完整 xpub policy、不读取私钥、
  不在设备端组合多签 raw tx。
- BTC 多签 SignTx host oracle 已覆盖 `SPENDMULTISIG`/P2SH、`SPENDWITNESS`/P2WSH、
  `SPENDP2SHWITNESS`/P2SH-P2WSH 三种输入变体的完整 prev_tx 请求链。门禁还覆盖
  prevout scriptPubKey 不匹配拒绝，以及 P2WSH input 搭配 P2SH multisig 找零时
  不能被误识别为同 policy 找零。
- BTC 多签 digest/raw-tx 结构门禁已独立落到 `bitcoin/multisig_tx.*`：模块只接收
  normalized policy、公开交易字段和 compact signature，不读取私钥，也不调用 signer。
  它会再次校验 redeem script/pubkey 顺序、P2SH/P2WSH hash 绑定、verified prevout、
  policy fingerprint、同 policy 找零、金额与 fee/UI 摘要，再使用 libwally 构造
  legacy sighash、BIP143 sighash、scriptSig/witness 和 raw tx。
- BTC 多签 partial-signing 的 slot 语义已有 host gate：实现遵循 Trezor/OneKey
  `MultisigRedeemScriptType.signatures` 规则，signatures 数组按 multisig pubkey slot
  对齐，空项表示该 cosigner 未签。本机只会在自己的 pubkey slot 为空、已有签名未达到
  threshold、已有签名都是 canonical DER 时，才允许把本机 DER 签名填入该 slot。该门禁
  覆盖 `PRESERVED` 和 `LEXICOGRAPHIC` pubkey order，并拒绝本机 slot 已签、threshold
  已满足、畸形 DER 的输入。该模块只处理公钥、脚本、已有签名和本机签名结果，不读取私钥。
- 第三方 oracle 使用 `trezorlib` 构造 multisig protobuf、使用 `embit` 重新计算
  P2SH legacy digest 与 P2WSH/P2SH-P2WSH BIP143 digest，并独立解析 raw tx，核对
  DER+SIGHASH_ALL 签名位置、redeem/witness script、outpoint、sequence、付款金额、
  multisig 找零、fee、完整 signer path 和 UI summary。BIP45 legacy 与主网/测试网 BIP48
  P2SH/P2WSH/P2SH-P2WSH 都有正向门禁；错误 prevout、错误 witness program、签名数量不足、
  外部分支冒充找零、账户/coin/script-purpose 不匹配、索引越界都有拒绝门禁。
  fake signatures 只用于 raw-tx 结构测试；slot-aware partial gate 验证公开签名槽规则。
  标准 `SignTx/TxAck` 多签路径还会把设备返回的真实 DER partial signature 写入
  `embit.psbt`，由第三方 PSBT round-trip 和独立 finalization 检查签名、公钥 slot、
  redeem/witness script、output 金额与最终 raw tx 结构。
- BTC Trezor-compatible USB session 已开放受限 multisig partial signing：pending `SignTx`
  包含 multisig input/output 时，会先走受限 preview/confirm，然后用保存的公开 redeem script
  重新校验本机 signer path、公钥 slot、prevout script hash、金额、fee 和找零 policy，再调用
  统一 `wallet_core_sign_digest_ecdsa_recoverable()` 签 digest，返回 `TxRequest.serialized.signature`
  和 input-level `signature_index` 给 Sparrow/协调器组合。session 不保存完整 xpub policy，不读取私钥，
  redeem script 通过堆按需保存并在 reset/失败路径释放。
- BTC multisig USB session 仍不是完整 PSBT/协调器实现：当前返回本机 partial signature，
  不在设备端组合多方签名，不生成完整 multisig raw tx 给主机。
- BTC fee-rate 估算已补保守 multisig 估算：只使用 threshold、signer count 和
  P2SH/P2WSH/P2SH-P2WSH variant，不读取 redeem script、xpub、signature 或私钥材料。
- BTC `SignTx` 的 singlesig basic policy 仍必须拒绝 `has_multisig` 的 input/output；
  multisig 只走专门 preview/confirm/digest 分支，避免单签 raw-tx builder 被多签输入绕过。
- Sparrow/lark 的 singlesig xpub 导入会用默认 `SPENDADDRESS` 调
  `GetPublicKey(m/49'...)` / `GetPublicKey(m/84'...)`。固件现在只在账户级 public-node
  导出路径把这个默认值视为客户端兼容占位，并按 BIP purpose 推断 ypub/zpub；
  签名路径仍然要求 input `script_type` 与 prevout/script policy 严格匹配。

继续要求：

- 每次新增链层/协议层文件，都必须被 sensitive key boundary gate 覆盖。
- 新增 signer 只能调用 `wallet_core_sign_digest_ecdsa_recoverable()` 或未来统一 signer API。
- 不允许新增 `get_private_key()`、`wallet_get_hdkey(... PRIVATE ...)` 到链层/协议层。

### Phase EVM-Safe: Safe 2/3 多签与 USDT 签名

目标：支持 Safe 2-of-3 这类 EVM 多签使用场景时，设备只作为其中一个
Safe owner 签名，不在固件内管理多个 owner 私钥，也不尝试替代 Safe 合约
threshold 逻辑。固件要做的是解析并确认 SafeTx，再对 EIP-712 digest 签名。

参考优先级：

- Safe 官方合约/文档与 EIP-712 规范。
- Safe 官方 `safe-cli` / `safe-eth-py`：作为第三方 oracle 和 host gate
  数据来源。尤其参考 `SafeTx.eip712_structured_data`、
  `safe_eth.eth.eip712.eip712_encode()`、
  `trezorlib.ethereum.sign_typed_data_hash()` 的使用方式。
- Trezor official `EthereumSignTypedData` / `EthereumSignTypedHash`
  protobuf 和 Connect 行为。
- OneKey Pro 的 Safe 实践只作架构参考：
  `core/src/apps/ethereum/onekey/sign_safe_tx.py` 把 SafeTx 作为
  typed-data 子路径处理，`messages-ethereum-eip712-onekey.proto` 用
  `EthereumGnosisSafeTxRequest/Ack` 拉取 SafeTx 字段；这个分层思路值得吸收，
  但 OneKey 私有 message id 不能当作 MetaMask/Trezor 标准。

隔离原则：

- 不改现有 `EthereumSignTx` / `EthereumSignTxEIP1559` 普通 ETH/ERC20
  签名主流程。
- 新增 Safe 能力放在独立子路径：

```text
protocols/trezor/ethereum/typed_data.*
  -> protocols/trezor/ethereum/safe_normalizer.*
  -> chains/ethereum/eip712.*
  -> chains/ethereum/safe_tx.*
  -> chains/ethereum/safe_confirm.*
  -> wallet_core_sign_digest_ecdsa_recoverable()
```

- 普通 ETH 交易继续走：

```text
protocols/trezor/ethereum/normalizer.*
  -> chains/ethereum/tx_request.*
  -> chains/ethereum/tx/digest/confirm/sign.*
```

- `chains/ethereum/safe_*` 只能接收已归一化的 SafeTx 字段，不能直接解析
  Trezor wire，也不能调用 seed/mnemonic/xpriv/raw private key API。
- `protocols/trezor/ethereum/typed_data.*` 只负责 message decode/encode 和
  session 状态，不直接生成 UI 文案，不直接调用 signer。

trezorlib / Safe CLI 兼容路径：

- `trezorlib` 不直接理解 Safe 2/3 threshold，也不校验 Safe owners；Safe
  语义由 `safe-cli` / `safe-eth-py` 生成的 `SafeTx.eip712_structured_data`
  承担。
- `safe-cli` 的硬件钱包路径会先用
  `safe_eth.eth.eip712.eip712_encode(eip712_message)` 生成
  `domain_hash` 和 `message_hash`，再调用
  `trezorlib.ethereum.sign_typed_data_hash(client, n, domain_hash, message_hash)`。
- `trezorlib.sign_typed_data_hash()` 发出的设备消息是
  `EthereumSignTypedHash`，字段为：
  - `address_n`
  - `domain_separator_hash`
  - `message_hash`
  - optional `encoded_network`
  官方 Trezor 设备在 hash-only 模式下可返回
  `EthereumTypedDataSignature(address, signature)`，但这不能让设备展示
  SafeTx 收款人、USDT 金额等关键资金信息。
- 为避免盲签，SafeTx 首版采用 OneKey 风格二阶段扩展：
  1. host 发官方 `EthereumSignTypedHash`。
  2. 设备返回 `EthereumGnosisSafeTxRequest`（message id 20119，空
     payload），要求 host 提供 SafeTx 明文字段。
  3. host 回 `EthereumGnosisSafeTxAck`（message id 20118），字段按
     OneKey proto：
     `to/value/data/operation/safeTxGas/baseGas/gasPrice/gasToken/refundReceiver/nonce/chain_id/verifyingContract`。
  4. 设备重新计算 `domain_hash/message_hash/signing_hash`，和第 1 步的
     typed-hash 入参逐字节绑定；不一致直接拒绝。
- 因此首版硬件通信优先级是：
  1. 实现 `EthereumSignTypedHash -> EthereumGnosisSafeTxRequest ->
     EthereumGnosisSafeTxAck` 的非盲签二阶段流程。
  2. 在 host gate 中用 `safe-cli` 生成 SafeTx hash，用设备/本机 harness
     返回签名，再用第三方库 recover signer。
  3. 后续再实现完整 `EthereumSignTypedData` 的
     `StructRequest/StructAck/ValueRequest/ValueAck` 交互流，供 MetaMask
     或其他 dApp 直接传 typed data 时使用。
- 风险限制：如果只有 `domain_hash/message_hash` 而没有完整 SafeTx 字段，
  设备不能展示 USDT 收款人/金额等人类可读内容。首版若走 hash-only
  模式，必须同时要求 host 提供可校验 SafeTx payload，或把 hash-only
  签名限制为“显示 domain/message hash 的高级模式”，默认不用于资金转账。

首版安全子集：

- 只开放 `primaryType == "SafeTx"`。
- 只开放 SafeTx 字段：
  `to/value/data/operation/safeTxGas/baseGas/gasPrice/gasToken/refundReceiver/nonce`。
- `domain.chainId` 必须非零，`domain.verifyingContract` 必须是 20 字节地址。
- `operation == CALL` 才默认允许；`DELEGATE_CALL` 首版拒绝，后续若开放必须
  单独强提示和门禁。
- SafeTx `data` 首版只清晰解析：
  - ERC20 `transfer(address,uint256)`
  - ERC20 `approve(address,uint256)`
  - 空 calldata / native value transfer
- USDT 这类 token metadata 必须绑定 `chain_id + token_contract + decimals`。
  未知 token 不得显示可信 symbol，只显示合约地址和 raw uint256 amount。
- 固件不联网查询 Safe owners/threshold。若要显示 2/3 owner policy，必须由
  主机提供 Safe 配置并让用户确认，或由设备缓存用户确认过的 Safe policy。
  在没有可信 policy 时，屏幕必须明确显示“Signing as owner”和 Safe 地址，
  不能假装已验证完整 2/3 成员集合。

必须门禁：

- `safe-cli` / `safe-eth-py` oracle：
  构造 SafeTx、USDT transfer、USDT approve，生成
  `domain_hash/message_hash/safe_tx_hash`，与本仓 C 实现逐字节比对。
- `ethers.js` 或 `viem` oracle：
  独立计算 EIP-712 hash、ABI decode、signature recover，避免只用 Safe
  Python 栈自测。
- Trezor protocol host harness：
  模拟 `EthereumSignTypedHash -> EthereumGnosisSafeTxRequest ->
  EthereumGnosisSafeTxAck`，验证 hash-only 不会直接签名，SafeTx Ack
  必须完成字段解析和 hash 绑定；签名后验证
  `EthereumTypedDataSignature` 返回格式、address、signature recover。
- UI 摘要门禁：
  Safe 地址、chain id、nonce、to/value、token contract、
  recipient/spender、amount、safeTxGas/baseGas/gasPrice、SafeTx hash
  每页行数不能超过 T-Display-S3 当前 dialogs 限制。
- 负向门禁：
  缺字段、超长 calldata、畸形 uint256、错误地址长度、未知 primary type、
  非零/异常 gas token、delegatecall、chainId/domain mismatch、token metadata
  contract mismatch 均必须拒绝或进入明确强提示策略。

后续分阶段：

1. Host-only Safe oracle gate：只新增测试脚本，不碰固件签名路径。
2. `chains/ethereum/eip712.*`：实现 SafeTx 最小 hash 子集，并用
   `safe-cli`/`ethers` 双 oracle 对照。
3. `chains/ethereum/safe_tx.*`：实现 SafeTx 字段校验和 ERC20/USDT 摘要模型。
4. `protocols/trezor/ethereum/typed_data.*`：接入 Trezor
   `EthereumSignTypedHash`，优先支持 host 已提供
   `domain_separator_hash/message_hash` 的模式。
5. UI 确认和硬件签名：确认通过后只调用统一 digest signer，返回
   `EthereumTypedDataSignature`。
6. 再评估完整 `EthereumSignTypedData` struct/value request flow、Safe
   `execTransaction` raw transaction 解析、Safe message signing。

当前进度：

- `chains/ethereum/safe_tx.*` 已实现 SafeTx domain/message/final signing
  hash、字段校验和 ERC20 transfer/approve 摘要，门禁用
  `safe-cli` 底层 `safe-eth-py` 与 `eth_account.encode_typed_data` 双 oracle
  交叉校验。
- Trezor `EthereumSignTypedHash` message id 470 已接入 parser、dispatcher、
  trace 和 trezorlib host harness。当前返回
  `EthereumGnosisSafeTxRequest`，进入 SafeTx payload 二阶段流程，不会
  触发本机解锁、UI、私钥或签名路径。
- `protocols/trezor/ethereum/safe_normalizer.*` 已补 SafeTx payload 绑定
  模型：host 提供结构化 SafeTx 字段，固件重新计算
  `domain_hash/message_hash/signing_hash` 并与 `EthereumSignTypedHash`
  入参逐字节绑定；chainId/hash/encoded_network/delegatecall/超长 calldata
  负向门禁已覆盖。
- `EthereumGnosisSafeTxAck` parser 已按 OneKey 字段布局实现，缺字段、
  重复字段、未知字段、错误地址、畸形 uint256/leading zero、超长 data
  均拒绝。
- SafeTx 结构化 UI 摘要已接入：绑定通过后显示 path、chain id、nonce、
  Safe 地址、token contract、recipient/spender、amount、
  safeTxGas/baseGas/gasPrice、SafeTx signing hash；所有字段走
  `chain_confirm_summary_t` 和 T-Display-S3 行数门禁。
- SafeTx 首版真实签名已接入：`session.c` 只把已绑定的 typed hash、
  SafeTx、summary、signing_hash 交给 `wallet_adapter` callback；
  `wallet_adapter` 负责 UI 确认后调用
  `wallet_core_sign_digest_ecdsa_recoverable()`，协议层和链层不获取
  raw private key。
- `tools/run_external_oracle_gates.py` 已补 SafeTx 二阶段 raw-wire oracle：
  使用 `safe-eth-py`/`eth_account` 生成 SafeTx hash，用第三方 `eth_keys`
  recover `EthereumTypedDataSignature(r||s||recid)`，验证 signer address
  与测试私钥地址一致。

后续缺口：

- 完整 `EthereumSignTypedData` struct/value request flow 还未接入。
- Safe owner/threshold/policy 仍未由设备验证；当前只确认并签名 SafeTx，
  不声称设备已验证 2/3 owner 集合。
- 非零 `gasToken/refundReceiver` 首版拒绝；后续若支持 gas token/refund
  receiver，需要把它们加入强提示 UI 和独立 oracle/负向门禁。

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
- `script_builder.c/h` 已独立，集中 BTC Trezor-compatible 路径里的 external output
  scriptPubKey、change scriptPubKey、legacy P2PKH scriptSig、P2SH-P2WPKH scriptSig
  和 signing scriptCode 构造。它只取公钥，不读取私钥，为后续 `normalizer.c/h`
  拆分和 raw tx oracle 对齐做准备。
- `normalizer.c/h` 已开始落地，当前先承接 `signing_state -> bitcoin_confirm_request_t`
  的转换，包括 singlesig basic 确认摘要和 multisig preview 确认摘要。session
  现在显式依赖 normalizer；`protocol.c` 不再承担 UI review model 转换职责。

下一步建议顺序：

1. 继续扩展 `bitcoin/normalizer.c/h`
   - 把后续 BTC descriptor/policy、PSBT、multisig review model 继续放在 normalizer/approver
     层，不回填到 USB session 或 raw tx serializer。

2. `bitcoin/signing_state.c/h` 后续完善
   - 已有 prev_tx request/ack collect/verify host harness。
   - 已补 scriptPubKey 与派生路径/脚本类型绑定。
   - 已补 legacy/P2PKH、P2SH-P2WPKH 的真实硬件 trezorlib 测试入口，测试端用
     `embit` 独立验证 raw tx 结构、scriptSig/witness、签名有效性和 xpub 派生公钥一致性。

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
   - 验证 legacy/P2SH-P2WPKH 会请求 prev_tx、校验 txid/prevout amount。
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

- 在真实设备上跑通 `--include-legacy`，记录 P2PKH/P2SH-P2WPKH 的 Sparrow/OneKey
  导入和签名表现。
- Sparrow/OneKey 完整导入兼容：`GetPublicKey`、`GetAddress`、`show_display`、
  `ignore_xpub_magic`、model/version/internal_model、firmware range 仍需真实客户端矩阵测试。
- P2WSH/P2SH multisig 的 xpub-only 导入和 `GetAddress.multisig` 已开放；
  标准 Trezor `SignTx/TxAck` 路径已开放受限 multisig partial-signing。它们不是简单 xpub
  版本字节问题，必须继续维护 descriptor/multisig/pubkey order/witnessScript/change
  policy/fee review 门禁；未知 witness script、policy 不绑定、prevout 不匹配仍必须拒绝。
- Trezor `MultisigRedeemScriptType` normalizer 已开始落地：能解析 old-style
  `pubkeys[]` 与 new-style `nodes[] + address_n`，拒绝 `HDNodeType.private_key`、
  hardened suffix、`m > n`，并转换为内部 multisig policy/redeem script/scriptPubKey。
  这仍是前置安全层，不等于开放 multisig 地址或签名。
- BTC `GetAddress`、`TxInputType`、`TxOutputType` 的 `multisig` 字段已接入 decode：
  合法 multisig 请求会完成 normalizer。`GetAddress` 会额外保留完整 policy 供本机 signer
  membership 校验；`TxInputType`/`TxOutputType` 仍只保存小型 summary，签名阶段只额外按需
  保存公开 redeem script。协议状态不会把完整 multisig pubkey/policy 嵌入每个 input/output，以避免
  T-Display-S3/ESP32-S3 上的栈和状态内存膨胀。
- `script_policy` 已能用 `TxInput.multisig` summary 校验 prevout scriptPubKey：
  P2SH、P2WSH、P2SH-P2WSH 都覆盖正向路径，且会拒绝 threshold 无效、script_type/variant
  错配、prevout script 不一致。这个能力现在是受限 multisig partial-signing 的前置安全层。
- `multisig_policy_t` 已带 policy fingerprint，host gate 按 OneKey 的
  `MultisigFingerprintChecker` material 规则验证 old-style/new-style 一致性、pubkey order
  mode 不影响 fingerprint、threshold 变化会改变 fingerprint。该字段不写入 input/output
  summary，避免破坏 `trezor_bitcoin_tx_output_t <= 256` 等 ESP32 状态尺寸门禁。

4. P2SH-P2WPKH 已实验性开放。
   - P2SH-P2WPKH 继续使用 segwit v0/BIP143 sighash。
   - Host gate 增加测试签名注入：Python 用 `embit` 计算 sighash、`ecdsa`
     真实签名，C gate 组 raw tx，再由 Python 解析 scriptSig/witness 并验签。
   - 注入通道只存在于 host gate，不进入固件构建和 USB 协议。
   - base58 外部输出由统一 output script 解析器处理，不在 P2SH 签名路径里手写解析。

5. legacy P2PKH 已实验性开放。
   - 仅支持 BIP44 P2PKH 输入，且必须完成 prev_tx verified amount/script 绑定。
   - 使用 libwally `WALLY_SIGTYPE_PRE_SW` 生成 non-segwit sighash。
   - raw tx 使用标准 P2PKH `scriptSig = <DER+SIGHASH_ALL> <compressed_pubkey>`，
     不带 segwit marker/witness。
   - Host gate 使用 `embit` 计算 legacy sighash、`ecdsa` 生成真实签名，再解析
     设备返回 raw tx 并验签，避免本仓 C 代码自测自己。
   - 注入签名只存在于 host gate；固件仍然只走 wallet_core digest 签名边界，
     协议层/链层不读取 private key/seed/mnemonic。

6. legacy/base58 外部输出地址解析已实验性开放。
   - 支持主网/testnet P2PKH 和 P2SH base58check 地址输出。
   - 固件侧优先尝试 bech32，再调用 libwally `wally_address_to_scriptpubkey()` 解析 base58。
   - 确认 UI 之前会先验证 output script，错误网络/畸形地址不会进入签名确认摘要。
   - Host gate 使用 `base58` 生成地址、`embit.script` 生成期望 scriptPubKey，并验证
     signed raw tx 的输出脚本完全一致。
   - 已覆盖 testnet 交易发送到 mainnet base58 地址必须拒绝。

暂不做：

- 设备端组合完整 multisig raw tx 或替代 Sparrow/PSBT 协调器
- raw PSBT / OneKey `SignPsbt` 开放
- Taproot/BIP86 地址和 Schnorr 真签名开放
- external input / payjoin / replacement tx

### Phase 2.5: PSBT / multisig / Taproot 安全模型

这三块都影响资金安全，不能只靠“消息能解析”就开放。

1. PSBT
   - 原版 Jade native RPC 已有 `main/process/sign_psbt.c`。核心安全模型是：
     先解析 PSBT/PSET，识别 singlesig/multisig/Green multisig，再用本机 wallet/descriptor
     生成期望 script，与 PSBT 内 prevout/change/output 绑定校验，最后才签名。
   - Trezor-compatible 标准路径通常是主机把 PSBT 转成 `SignTx/TxAck` 交互；OneKey 另有
     `SignPsbt/SignedPsbt` 扩展。我们后续若接 OneKey 扩展，必须作为单独 adapter：
     限制 PSBT 总长度、input/output 数量、unknown map 大小、key/value 长度，并复用 Jade
     PSBT 策略，不让 raw PSBT parser 直接靠近 signer。
   - 当前策略：先完善标准 `SignTx/TxAck` 覆盖 Sparrow 常规 PSBT 流；只有真实客户端明确需要
     OneKey `SignPsbt` 时，再加“安全拒绝 -> host parser gate -> policy -> UI -> signer”的小步链路。
   - 当前代码只实现到 OneKey raw `SignPsbt` 的“安全拒绝”阶段：10052 `SignPsbt` 可被 trace
     识别，但固定返回 `Failure/DataError`。
   - Host gate 已用第三方 `embit.psbt` 构造并 round-trip 解析最小 PSBT，随后通过本机
     Trezor wire oracle 验证 OneKey `SignPsbt` 扩展消息必须返回 `Failure/DataError`。
     标准 Trezor `SignTx/TxAck` 多签路径还会把设备 partial signature 写入 `embit.psbt`
     并独立 finalization，验证 PSBT 协调器能消费该签名；raw PSBT payload 仍不会进入 signer。

2. multisig
   - 必须参考 OneKey/Trezor 的 `MultisigRedeemScriptType` 与原版 Jade descriptor/multisig
     代码，先做 request normalizer。
   - 原版 Jade 的 `main/multisig.c`、`main/descriptor.c`、`main/process/sign_psbt.c`
     可以复用的是脚本构造、descriptor 查找、PSBT 输入/输出校验思路；不能直接把 native
     CBOR RPC process 函数接进 Trezor USB adapter。Trezor `MultisigRedeemScriptType`
     必须先转换成内部 descriptor/policy 模型，再进入 UI 和 signer。
   - 开放前必须校验 `m/n`、xpub fingerprint、每个 cosigner pubkey 派生、`address_n`
     不含非法 hardened 后缀、script_type 与 redeem/witness script 匹配、change path 属于
     已登记 descriptor。
   - 当前已新增 `main/protocols/trezor/bitcoin/multisig.*` normalizer：
     解析 Trezor protobuf 后派生 cosigner 子公钥，构建 `MULTI_P2SH`、`MULTI_P2WSH`、
     `MULTI_P2WSH_P2SH` policy，并生成 redeem script/scriptPubKey 用于后续 prevout/change
     绑定。
   - `messages.c` 已把 `GetAddress.multisig`、`TxInputType.multisig`、
     `TxOutputType.multisig` 纳入解析。`GetAddress` 保留完整 policy 用于本机 signer
     membership 校验；input/output 只保留 scriptPubKey summary，完整 normalizer
     临时对象用完即清零，不进入长期 signing state。
   - `multisig_policy_t` 已生成 OneKey/Trezor 风格 fingerprint；host gate 验证
     old-style/new-style protobuf forms、BIP67 order mode 和 threshold 变化的 fingerprint
     行为。fingerprint 通过独立旁路数组进入 signing state，只用于 input policy 一致性和
     change-output matcher；完整 xpub/redeem policy 仍不进入长期 input/output summary。
   - Host gate 使用 `trezorlib` 生成 `MultisigRedeemScriptType` payload，使用第三方
     `embit.script.multisig()` 生成期望 redeem script，覆盖 old-style/new-style、
     BIP67 lexicographic 排序、private_key 字段拒绝、hardened suffix 拒绝、`m > n` 拒绝。
     由于当前 host gate 没有链接真实 libwally，BIP32 子派生只在生产固件路径由 libwally
     执行；host oracle 用已派生 child xpub + 空 suffix 避免 fake derivation 自测。
   - Host gate 已新增 BTC signing state 结构尺寸门禁，防止后续把完整 multisig 结构塞进
     每个 input/output，造成 ESP32 栈/堆压力。
   - descriptor/xpub/path/change 绑定完成前，只能开放 public-node 导入和
     `GetAddress.multisig` 地址确认。当前受限 signing 只允许已通过这些门禁的
     P2SH/P2WSH/P2SH-P2WSH partial signature。
   - 当前 gate 已覆盖 `GetAddress` multisig 正向路径、policy 不包含本机公钥的拒绝路径、
     `SignTx` multisig input/output 的拒绝路径，并新增 normalizer 级 policy/redeem
     script 门禁、`script_policy` prevout scriptPubKey 绑定门禁，以及 P2SH/P2WSH/
     P2SH-P2WSH digest/raw-tx 结构 oracle。session 已接入受限 partial signer；后续重点是
     硬件确认/取消回归、Sparrow/OneKey 实测和更多恶意 TxAck 状态机门禁。

3. Taproot / BIP86
   - OneKey/Trezor proto 的 `SPENDTAPROOT=5`、`PAYTOTAPROOT=6` 只是协议入口，不等于可签名。
   - 固件需要 BIP86 path policy、x-only pubkey/address oracle、BIP341 sighash、Schnorr signer
     和 UI 摘要绑定。当前 `wallet_core` 只有 ECDSA digest 签名边界，不能用 ECDSA 路径冒充
     Taproot。
   - 推荐顺序：先实现 BIP86 `GetPublicKey/GetAddress` host oracle 和明确 `SignTx`
     Taproot 拒绝；再加 Schnorr signer 边界；最后开放 Taproot 签名。
   - 当前 gate 已覆盖 `GetAddress`、`GetPublicKey`、`SignTx` Taproot script type 拒绝。
     在 x-only pubkey、BIP341 sighash、Schnorr signer 和 UI 摘要绑定完成前，不能开放。

4. UI 摘要门禁
   - BTC 签名 host gate 必须验证 review model 中 `Path/To/Amount/Change/Fee/FeeRate`
     与交易 policy 计算结果一致。
   - 所有新增 BTC 摘要字段必须通过 `test_confirm_summary_fits_tdisplay_s3()`，避免再次出现
     超过 T-Display-S3 对话框行数或分页约束导致的确认流异常。

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

1. legacy/P2PKH 与 P2SH-P2WPKH 硬件 trezorlib 测试
   - 覆盖真实 USB transport、本机确认 UI、真实 wallet_core 签名路径。
   - legacy P2PKH 重点确认 raw tx 不带 witness、scriptSig 标准且主机可验签。

2. Sparrow/OneKey 导入兼容矩阵
   - 分别测试 BIP44/P2PKH、BIP49/P2SH-P2WPKH、BIP84/P2WPKH、BIP45/P2SH multisig、
     BIP48/P2SH-P2WSH、BIP48/P2WSH 的账户 xpub 导入。
   - 覆盖 `ignore_xpub_magic=true/false`、`show_display=false`、model/version/internal_model。

3. PSBT/multisig/Taproot 先做 host gate 和安全拒绝
   - 标准 Trezor `SignTx/TxAck` 优先于 OneKey `SignPsbt` 扩展。
   - OneKey `SignPsbt` 已有第三方 PSBT oracle + wire 拒绝门禁。
   - multisig 已有 normalizer 级 policy/redeem script 门禁，但尚未接入
     descriptor/change/prevout/output 安全绑定；Taproot 已有 protocol-level 拒绝门禁。
     未完成这些安全模型前继续拒绝签名。

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
- 不开放 raw PSBT/Taproot 真签名，直到 descriptor/path/script policy、UI 摘要、
  raw tx/PSBT oracle 和真实硬件测试都完成。BTC multisig 当前只开放标准
  `SignTx/TxAck` 下的受限 cosigner partial signature。
- 不让 Ledger APDU 影响 chain core。Ledger 只能作为 adapter。
- 不让 USB 层直接调用 wallet_core signer；最终必须经 app service / chain policy / UI review。
