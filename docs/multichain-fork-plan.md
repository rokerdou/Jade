# Jade Fork Multichain Firmware Plan

本文档记录基于 Jade fork 开发 T-Display-S3 多链硬件钱包固件的初始架构计划。目标不是在 Jade 中临时塞入 ETH/TRON 代码，而是逐步把 Jade 演进成一个更清晰的多链固件底座。

## 目标

- 硬件目标：LilyGO T-Display-S3, ESP32-S3, 双按键, 内置 LCD。
- 第一批链：Bitcoin, Ethereum/EVM, Tron。
- 主机兼容：保留 Jade RPC 能力，新增 Trezor protocol compatibility layer，用于 MetaMask/Trezor Connect 兼容。
- 安全目标：保留 Jade 已有 seed/PIN/passphrase/storage/RNG/UI 确认能力，并在真实使用前收紧 debug、secure boot、flash encryption、JTAG/ROM download 等配置。

## 开发原则

- 安全优先：任何 seed、mnemonic、xprv、私钥和签名路径改动都按硬件钱包高风险代码审查。
- USB 主机不可信：USB 只做传输和协议解析，不能绕过解锁、链层解析、屏幕确认或直接触达私钥。
- 私钥不出 wallet core：链层只能请求公钥、地址材料或签名，不能读取或返回私钥材料。
- 架构分层：platform、wallet core、crypto、chains、protocols、ui flows 分层解耦，避免链逻辑散落到硬件层。
- 硬件相关代码优先参考 Jade 原实现，尤其是 T-Display-S3 显示、按键、电源、USB 和 flash/partition 配置。
- 标准协议优先参考成熟开源实现和测试向量；Trezor 代码只作行为参考，避免在 MIT fork 中直接复制 GPLv3 代码。
- 不把 Python 或脚本运行时引入固件本体；Python 只允许作为本机/CI 构建、生成、测试工具，并需要锁版本和 hash。
- 小步修改、小步验证：每次变更先做静态检查、格式检查和可构建性验证，再继续扩大范围。
- ETH/TRON 签名前必须先做本机派生地址校验；地址/私钥对应关系必须有正反向门禁测试，测试不过不得接入 USB/RPC 签名入口。
- 多链签名必须以硬件屏幕确认为准：主机 UI 只能辅助展示，不能替代设备屏幕上的链名、路径、from/owner、to、金额、token 合约、fee 上限和未知合约风险确认。
- 链负责“算出该签什么”，wallet core/crypto 只负责“对已授权 digest 签名”。链层不得获取裸私钥、seed、mnemonic、xprv 或任何可还原私钥的中间态。
- USB/protobuf 主机输入必须按恶意输入处理。畸形长度、未知 enum、缺失字段、超深/超长嵌套、超长 calldata、异常 derivation path 只能导致拒绝请求，不能导致越界、整数溢出、重启循环或敏感内存残留。

## 核心判断

采用第三条路线：

```text
Fork Jade -> 保留硬件和安全底座 -> 抽象 wallet core -> 新写 chain modules -> 新增 protocol adapters
```

不建议从零写。Jade 已经覆盖 ESP-IDF、T-Display-S3、显示、按键、USB/BLE、NVS、随机数、BIP39/BIP32、PIN/passphrase、sensitive memory clearing、OTA 和确认 UI 等高风险基础能力。

也不建议长期在 Jade 原架构内直接堆多链功能。Jade 的业务中心是 Bitcoin/Liquid，而目标产品是通用多链硬件钱包。需要尽早把 seed/key manager 与具体链实现解耦。

## 目标目录形态

长期目标目录可以演进为：

```text
main/
  platform/
    esp32s3/
      display/
      input/
      usb/
      ble/
      storage/
      rng/
      power/
  wallet_core/
    seed/
    bip39/
    bip32/
    passphrase/
    pin/
    key_manager/
  crypto/
    secp256k1/
    sha256/
    keccak256/
    base58/
    base58check/
    rlp/
    protobuf/
  chains/
    bitcoin/
      address/
      psbt/
      signing/
    ethereum/
      address/
      tx_legacy/
      tx_eip1559/
      erc20/
      personal_sign/
      eip712/
    tron/
      address/
      transaction/
      trc20/
      smart_contract/
  protocols/
    jade/
    trezor/
      transport/
      protobuf/
      messages/
      dispatcher/
    qr/
  ui_flows/
    confirm_address/
    confirm_tx/
    confirm_message/
    settings/
  app/
    main/
```

第一阶段不强行一次性移动所有文件。先引入新边界和新 API，再逐步迁移。

## Jade 保留边界

第一阶段尽量保留：

- T-Display-S3 BSP: `main/display_hw.c`, `main/power/tdisplays3.inc`, `main/input/*`
- USB CDC/RPC 队列：`main/serial.c`, `main/wire.c`, `main/process.c`
- Storage/NVS：`main/storage.c`
- RNG：`main/random.c`
- Sensitive memory cleanup：`main/sensitive.c`
- Seed/key lifecycle：`main/keychain.c`, `main/wallet.c`
- PIN server 机制：`main/process/pinclient.c`, `main/process/auth_user.c`
- UI 框架：`main/ui/*`, `main/gui.c`, `main/display.c`
- OTA 机制：`main/process/ota*.c`

需要逐步剥离或下沉的 Bitcoin/Liquid 业务：

- `main/process/sign_tx.c`
- `main/process/sign_psbt.c`
- `main/process/get_xpubs.c`
- `main/process/get_receive_address.c`
- `main/process/get_*blinding*`
- `main/utils/psbt.*`
- `main/descriptor.*`
- `main/multisig.*`

这些不应继续作为 wallet core 的中心，而应成为 `chains/bitcoin/` 的调用方或实现细节。

## Wallet Core API

链实现不直接访问全局 keychain。先定义一层统一密钥 API：

```c
typedef struct {
    uint32_t path[10];
    size_t path_len;
} derivation_path_t;

typedef struct {
    derivation_path_t path;
    uint32_t allowed_usage;
    uint32_t chain_id;
} wallet_key_handle_t;

bool wallet_core_is_unlocked(void);
bool wallet_core_is_initialized(void);
bool wallet_core_is_ready(void);
bool wallet_core_get_public_key(const wallet_key_handle_t* key, uint8_t* pubkey, size_t pubkey_len);
bool wallet_core_sign_digest(const wallet_key_handle_t* key, const uint8_t digest[32],
                             uint8_t* signature, size_t signature_len);
bool wallet_core_derive_shared_secret(const derivation_path_t* path, const uint8_t* peer_pubkey,
                                      size_t peer_pubkey_len, uint8_t* out, size_t out_len);
```

后续 BTC/ETH/TRON 都只能通过这层派生公钥、签 digest、导出地址需要的公钥信息。私钥不跨出 wallet core。

禁止形态：

```c
uint8_t* wallet_core_get_private_key(const derivation_path_t* path);
bool chain_sign_with_private_key(const uint8_t* private_key, ...);
```

目标形态：

```c
bool sign_digest(wallet_key_handle_t key, const uint8_t digest[32], uint8_t signature[65]);
```

安全含义：

- 链层负责规范化交易、校验路径/from/owner、生成待签 payload 和 digest。
- 授权层负责把“用户在屏幕看到的摘要”和“实际待签 digest”绑定。
- wallet core 负责根据 key handle 在内部派生私钥、调用 crypto primitive、清理 sensitive stack。
- crypto primitive 只看 digest 和内部私钥材料，不解析 ETH/TRON/BTC 交易，也不接触 USB/protobuf 消息。

## Chain API

协议层转换请求，链层负责业务验证和签名：

```c
typedef enum {
    CHAIN_BITCOIN,
    CHAIN_ETHEREUM,
    CHAIN_TRON,
} chain_id_t;

typedef struct {
    derivation_path_t path;
    uint64_t chain_id;
    const uint8_t* to;
    size_t to_len;
    const uint8_t* value;
    size_t value_len;
    const uint8_t* data;
    size_t data_len;
    uint64_t nonce;
    uint64_t gas_limit;
    uint64_t gas_price;
    uint64_t max_fee_per_gas;
    uint64_t max_priority_fee_per_gas;
} eth_sign_request_t;

typedef struct {
    derivation_path_t path;
    const uint8_t* raw_tx;
    size_t raw_tx_len;
} tron_sign_request_t;
```

协议层不做链签名细节，链层不感知 MetaMask/Trezor/Jade RPC。

## Trezor Reference Boundary

Trezor firmware 是 GPLv3，Jade 是 MIT。不要直接复制 Trezor GPL 源码进 Jade fork，除非决定整个项目按 GPLv3 发布。

协议规范优先级高于 Trezor。Trezor 是成熟实现参考和回归对照，不是 ETH/TRON/BTC 协议规范本身。若 Trezor 行为和公开协议规范、EIP/BIP/SLIP/TRON 官方文档不一致，必须在审查记录中明确说明差异，并默认优先按规范实现，除非兼容性需求经过单独威胁建模。

推荐方式：

- 阅读 Trezor ETH/TRON/BTC 行为和测试向量。
- 根据公开协议和链标准在 C 中重新实现，并用 Trezor 流程做二次校验。
- 用测试向量对齐地址、hash、签名、UI 字段和错误行为。

重点参考目录：

- `/Users/doujia/work/trezor-firmware/core/src/apps/ethereum`
- `/Users/doujia/work/trezor-firmware/core/src/apps/tron`
- `/Users/doujia/work/trezor-firmware/core/src/apps/bitcoin`

已对照的规范点：

- Ethereum 地址显示采用 EIP-55 mixed-case checksum：20 字节地址转小写 hex，Keccak256 小写 hex 字符串，再按 hash nibble 决定地址字母大小写。
- TRON 地址生成采用 TRON 官方账户算法：secp256k1 公钥 Keccak256 后取末 20 字节，前置 `0x41`，再 Base58Check。

## Trezor Compatibility Layer

`protocols/trezor/` 独立负责：

- USB framing / transport
- protobuf decode/encode
- Initialize / Features
- GetPublicKey
- EthereumGetAddress
- EthereumSignTx
- EthereumSignTxEIP1559
- EthereumSignMessage
- EthereumSignTypedData
- TronGetAddress
- TronSignTx

兼容层必须覆盖 BTC、ETH、TRON 三条主线，但开放顺序按门禁成熟度推进：

- BTC：复用 Jade 现有 Bitcoin/PSBT/地址能力，后续只做 Trezor protobuf adapter，不重新实现 BTC 链逻辑。
- ETH：优先实现 MetaMask/Trezor Connect 真实需要的 `Initialize/Features/EthereumGetAddress/EthereumSignTx/EthereumSignTxEIP1559`，但签名入口必须等 parser、UI 摘要和 digest 绑定门禁通过后再开放。
- TRON：先保留协议常量和链层能力，等 TRON raw transaction protobuf/sha256 和 TRC20 门禁补齐后，再开放 `TronGetAddress/TronSignTx`。

MetaMask 兼容优先级高于完整 Trezor 模拟。第一阶段只实现 MetaMask/Trezor Connect 真实需要的子集。

第一阶段 Trezor dispatcher 必须使用 allowlist，仅允许 `Initialize`、`GetFeatures`、`EthereumGetAddress` 进入协议处理。以下类型即使 Trezor 协议支持，也默认拒绝，直到有单独威胁建模和门禁测试：`LoadDevice`、`ResetDevice`、`RecoveryDevice`、`BackupDevice`、`GetEntropy`、`CipherKeyValue`、`GetECDHSessionKey`、`UnlockPath`、`PassphraseAck`、`DebugLink*`、任意签名消息、任意公钥/xpub 导出消息。

Trezor-HID-only/T-Display-S3 hardened 构建不依赖 Jade app CBOR transport 保存钱包。首次创建/恢复后必须在设备屏幕输入并确认 PIN；固件用本机 KDF 生成 AES key 后调用现有 `keychain_store()` 加密保存。该路径避免 USB 主机参与私钥持久化，但因不启用 Flash Encryption/Secure Boot 且无安全元件，不具备 Jade blind oracle 对完整 flash dump 的离线 PIN 猜测保护。

注意：协议兼容不等于自动被 MetaMask 发现。还需要处理 USB descriptor、VID/PID、Features response、model name、firmware version 和 Trezor Connect discovery 逻辑。

## USB Security Invariants

USB 主机必须按完全不可信处理。后续任何 Jade RPC 或 Trezor-compatible USB 方法都必须满足：

- USB transport 只负责 framing、长度限制、CBOR/protobuf 解码和响应编码，不直接调用 seed/keychain/private-key API。
- 任何导出类接口只允许返回公钥、xpub、地址、签名、交易结果等非私钥材料，禁止返回 seed、mnemonic、xprv、裸私钥、chain code 加私钥组合或任意可还原私钥的中间态。
- 任何签名接口必须先完成链层解析和策略检查，再显示链特定摘要，用户确认后才可调用 `wallet_core` 签名 primitive。
- 禁止新增“host supplies digest, device blindly signs”的外部 RPC；如测试需要，必须仅在 `CONFIG_DEBUG_MODE` 下编译，并确保 hardened/production config 无法启用。
- 当前 ETH/TRON 授权层只返回 `chain_authorization_t`，不签外部传入 digest。内部 digest 必须先转成 `chain_authorized_digest_t`，其中包含确认摘要绑定哈希和待签 digest 绑定哈希。后续真正签名 API 必须由固件 parser/encoder 生成 digest，并和同一个规范化请求及 UI 摘要绑定。
- 解锁状态必须绑定消息来源。USB 发起的敏感操作只能使用由同一 USB source 解锁的 keychain，不允许 BLE/QR/内部来源解锁后被 USB 复用。
- USB 可被嗅探，因此协议返回中不得包含秘密；host 能看到的签名、公钥、地址和交易明文都必须被视为公开或用户已同意公开。
- USB 可被注入，因此所有 parser 都需要固定最大长度、结构化解析、错误退出和不信任长度字段；异常输入只能导致拒绝请求，不能导致重启循环、内存破坏或密钥材料留存。
- Protobuf/Trezor parser 是攻击面。优先采用成熟、可配置上限的 protobuf/nanopb 类实现；若保留本项目轻量 parser，则只允许解析必要子集，并必须有 malformed corpus 门禁覆盖：`length=0xffffffff`、超长 varint、截断字段、未知 enum、重复字段、缺失必填语义、嵌套 definitions、超长 bytes/string、超长 calldata、超长/异常 path。
- parser 输出必须复制到固定上限的固件-owned 结构中，链层不得持有指向 USB RX buffer 的长期指针；解析失败必须清零临时 buffer 并返回 `Failure/DataError` 或等价错误。
- OTA 只能在新设备或已解锁设备上进入，固件必须校验 chip、board/features、secure version、hash，并要求用户在屏幕确认。
- Hardened build 必须关闭 debug RPC、console、USB DFU、USB MSC、USB networking、敏感日志和 BLE，除非某个功能明确需要并经过单独威胁建模。
- 真正存放资产前，必须完成 secure boot、flash encryption、JTAG/ROM download 限制、anti-rollback 和生产烧录流程审计；T-Display-S3 本身没有安全芯片，物理攻击仍是主要残余风险。

当前 USB 增量：

- 已新增只读 `get_eth_address` / `get_tron_address` Jade RPC 方法。
- 两个方法都要求当前消息源已解锁，只接受有最大长度限制的 `path` 参数，并按 ETH/TRON 路径规则校验。
- 两个方法只调用地址派生封装，显示硬件确认页后返回公有地址字符串，不返回 pubkey、xpub、seed、mnemonic、xprv、私钥、签名或任何私钥加密材料。
- 已新增 ETH 规范化交易请求结构 `ethereum_tx_owned_request_t`，用于后续 USB CBOR/protobuf parser 把外部输入复制进固定上限的固件内存，并拒绝超长 calldata、非规范 uint256 value、错误路径、缺失 `to` 和暂不支持的 EIP-2930。
- 暂不注册 ETH/TRON USB 签名入口；签名前必须先完成完整 transaction parser、UI 摘要绑定和签名 digest 门禁。

## Compile-Gate Test Priority

必须阻断构建的资金安全门禁：

- 私钥/公钥到 ETH/TRON 地址映射：含 secp256k1 公钥、ETH Keccak 后 20 字节、EIP-55 checksum、TRON `0x41` 前缀和 Base58Check。
- 派生路径校验：币种 coin type、account/index 上限、TRON owner/ETH sender 与本机派生地址不一致时拒绝。
- 交易报文 signing payload/digest：ETH legacy/EIP-155、EIP-1559、ERC20/TRC20 transfer/approve、TRON raw transaction protobuf/sha256。
- UI 授权绑定：同一个硬件确认摘要必须绑定同一个规范化请求和 digest，不能确认 A 后签 B。
- USB 签名入口：不得存在 host-supplied digest blind signing；所有输入长度和结构字段必须有边界测试。
- USB/protobuf parser 恶意输入：长度溢出、varint 溢出、截断消息、未知/重复字段、错误 wire type、异常 enum、超长 calldata、超长 definitions、异常 derivation path 必须拒绝且不能 crash/reset。
- Key boundary：链层和协议层不得链接或调用任何 `get_private_key` 类 API；签名只能经由 `wallet_core_sign_digest(key_handle, digest, signature)` 形态的内部接口完成，私钥派生和清理由 wallet core 独占。

暂不作为第一批硬门禁的内容：

- UI 文案精确措辞、分页美化和非安全显示细节。
- 全量 token symbol/name 数据库；未知 token 默认显示合约地址并额外确认。
- 所有历史/边缘路径格式；先覆盖主流 BIP44/Trezor/Ledger 兼容路径并拒绝不认识的格式。

## UI Confirmation Invariants

多链支持会直接影响硬件屏幕交互。屏幕确认不是“体验层”，而是签名安全边界：

- 实现顺序必须先于签名/USB 接入：先落链层 preflight 和 UI 确认摘要结构，再做硬件确认 flow，最后才允许接入 USB/RPC 签名入口。
- 任何签名调用进入 `wallet_core` 前，必须先由链层 preflight 输出一个结构化确认摘要，再由 UI flow 在设备屏幕显示并等待物理按键确认。
- ETH/TRON 确认页至少显示链名、派生路径、from/sender 或 TRON owner、recipient、原生币金额、最大手续费或 fee limit。
- ERC20/TRC20 转账必须显示 token 合约地址、recipient、amount；未知 token 不能只显示 symbol，必须显示合约地址并要求额外确认。
- `approve` 必须和 `transfer` 分开显示，spender/amount 必须突出；无限授权或最大 uint256 授权需要单独高风险确认。
- 未知合约 calldata 默认拒绝。若未来允许“未知合约风险确认”，必须在设备屏幕明确显示 contract address、calldata hash/摘要、fee 上限，并要求额外确认；不得提供无 UI 的盲签入口。
- TRON `owner_address` 与本机派生 signer address 不一致必须拒签；不能只提示后继续。
- 所有 UI 字段来自链层结构化解析结果，不直接信任主机传来的显示字符串。
- T-Display-S3 屏幕较小，长地址必须使用分段/滚动/校验码形式，不能截断到无法区分；确认按钮流程必须防误触。

## ETH Digest Correctness Gates

ETH 交易 digest 生成必须同时满足 Trezor 流程对照和官方 EIP 向量：

- Legacy/EIP-155 字段顺序对照 Trezor `core/src/apps/ethereum/sign_tx.py`：`nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0`。
- EIP-1559 字段顺序对照 Trezor `core/src/apps/ethereum/sign_tx_eip1559.py`：`0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])`。
- 编译门禁必须包含 EIP-155 官方 signing data/hash 向量。
- EIP-1559 第一阶段只允许空 access list；EIP-2930/type 1 在 digest builder 中显式拒绝，等解析/UI/门禁补齐后再启用。
- `nonce` 必须进入硬件确认摘要和授权绑定，避免只改 nonce 的交易复用同一个确认摘要。

## Phase Plan

### Phase 0: Fork Hygiene

- 保持 `master` 可回退。
- 在 `codex/multichain-tdisplay-s3-plan` 上记录架构计划。
- 明确项目名称、License 策略、是否接受 GPLv3 代码。
- 明确开发固件和资产固件的配置差异。

### Phase 1: T-Display-S3 Secure Baseline

- 以 `configs/sdkconfig_display_ttgo_tdisplays3.defaults` 为起点。
- 关闭 `CONFIG_DEBUG_MODE` 用于非测试固件。
- 默认关闭 BLE，后续按需打开。
- 关闭日志输出和 Wi-Fi logging。
- 建立单独配置：`sdkconfig_display_ttgo_tdisplays3_secure.defaults`。
- 先不熔 eFuse，等流程稳定后再做 secure boot / flash encryption 真机收口。

### Phase 2: Wallet Core Boundary

- 新增 `main/wallet_core/`。
- 对 `keychain.c` 和 `wallet.c` 做薄封装。
- 所有新链只调用 wallet core。
- 将确认 UI 与签名 API 拆开：链层生成可展示摘要，UI 层确认，wallet core 只签 digest。

### Phase 3: Ethereum MVP

最低可用集：

- derivation path: `m/44'/60'/0'/0/0`
- secp256k1 public key -> Ethereum address
- Keccak-256
- RLP
- legacy tx with EIP-155
- EIP-1559 tx
- personal_sign
- ERC20 transfer clear display

暂缓：

- EIP-712 typed data
- blind signing policy
- token registry 自动更新
- arbitrary contract clear signing

### Phase 4: Trezor ETH Compatibility

- 实现 protobuf message subset。
- 将 Trezor ETH request 转成 `eth_sign_request_t`。
- 返回 Trezor-compatible signatures。
- 用 MetaMask/Trezor Connect 做端到端测试。

### Phase 5: Bitcoin Re-home

- 保留 Jade 现有 BTC 能力。
- 将地址、xpub、PSBT、message signing 逐步迁入 `chains/bitcoin/`。
- 保持 Jade RPC 行为不破坏。

### Phase 6: Tron MVP

最低可用集：

- derivation path: `m/44'/195'/0'/0/0`
- secp256k1 public key -> Tron address
- TRX transfer
- TRC20 transfer
- TriggerSmartContract 常见字段展示

Trezor Tron 目录可作为行为参考，但不直接复制源码。

### Phase 7: Security Closure

- 编译期禁止 debug RPC。
- 禁止 unattended CI。
- 关闭不必要 transport。
- 开启 secure boot v2。
- 开启 flash encryption release mode。
- 禁用 JTAG。
- 禁用 ROM download mode。
- 审查 USB descriptor 和 host discovery。
- 审查所有 chain export/sign 接口是否有本机确认。
- 增加 fuzz/test vectors：CBOR, protobuf, RLP, Tron protobuf/raw tx。

## Immediate Next Steps

1. 创建 secure T-Display-S3 配置文件。
2. 新增 `wallet_core` API 头文件和空实现，先封装当前 keychain/wallet。
3. 新增 `chains/ethereum` skeleton，先实现 address derivation 单元测试。
4. 新增 `protocols/trezor` skeleton，不接 USB，只做 protobuf request -> internal request 转换测试。
5. 建立 test vector 目录，放 ETH/TRON/BTC 的地址和签名对照数据。
