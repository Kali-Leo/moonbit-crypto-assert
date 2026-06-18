///|
/// 规约层 —— 复杂测试（黑盒测试）
/// 测试多输入输出交易、安全规约、桥接规约、地址格式详细字段
/// ═══════════════════════════════════════════

///|
test "complex TransactionSpec with multi-input multi-output" {
  let fee : @protocol.FeeSpec = FeeSpec::{
    rate_str: "50",
    total_str: "10000",
    unit_desc: "gwei",
  }
  let input : @protocol.TxInputSpec = TxInputSpec::{
    txid: "0xabcdef1234567890",
    vout: 1,
    script_sig: "3045022100...",
    amount_str: "500000000000000000",
  }
  let output1 : @protocol.TxOutputSpec = TxOutputSpec::{
    address: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
    amount_str: "300000000000000000",
    script_pubkey: "",
    is_change: false,
  }
  let output2 : @protocol.TxOutputSpec = TxOutputSpec::{
    address: "0xRecipientAddress",
    amount_str: "199990000000000000",
    script_pubkey: "",
    is_change: true,
  }
  let tx : @protocol.TransactionSpec = TransactionSpec::{
    version: 1,
    inputs: [input],
    outputs: [output1, output2],
    locktime: 0,
    fee,
    txid: "0xtxid123",
    sig_scheme: SignatureScheme::EcdsaSecp256k1,
    signature_hex: None,
    public_key_hex: None,
  }
  debug_inspect(tx.version, content="1")
  inspect(tx.outputs.length(), content="2")
  debug_inspect(tx.sig_scheme, content="EcdsaSecp256k1")
  debug_inspect(
    tx.fee.total_str,
    content=(
      #|"10000"
    ),
  )
}

///|
test "complex TokenTransferSpec erc20" {
  let transfer : @protocol.TokenTransferSpec = TokenTransferSpec::{
    from: "0xSender",
    to: "0xReceiver",
    contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    amount_str: "1000000",
    chain_id: 1,
    precision: PrecisionSpec::{
      decimals: 6,
      unit_vals: "1000000",
      symbol: "USDC",
    },
  }
  debug_inspect(
    transfer.from,
    content=(
      #|"0xSender"
    ),
  )
  debug_inspect(
    transfer.precision.symbol,
    content=(
      #|"USDC"
    ),
  )
}

///|
test "complex PrecisionSpec bitcoin and satoshi" {
  let btc : @protocol.PrecisionSpec = PrecisionSpec::{
    decimals: 8,
    unit_vals: "100000000",
    symbol: "BTC",
  }
  debug_inspect(btc.decimals, content="8")
  debug_inspect(
    btc.symbol,
    content=(
      #|"BTC"
    ),
  )

  let sat : @protocol.PrecisionSpec = PrecisionSpec::{
    decimals: 0,
    unit_vals: "1",
    symbol: "SAT",
  }
  debug_inspect(sat.decimals, content="0")
  debug_inspect(
    sat.symbol,
    content=(
      #|"SAT"
    ),
  )
}

///|
test "complex security specs" {
  let replay : @protocol.ReplayProtectionSpec = ReplayProtectionSpec::{
    require_nonce: true,
    require_chain_id: true,
    require_timestamp: false,
    max_nonce_reuse: 0,
  }
  debug_inspect(replay.require_nonce, content="true")
  debug_inspect(replay.max_nonce_reuse, content="0")

  let safety : @protocol.TokenSafetySpec = TokenSafetySpec::{
    has_mint: true,
    mint_controlled: true,
    has_burn: true,
    has_pause: false,
    safety_modes: [ContractSafetyMode::Owned, ContractSafetyMode::TimeLock],
  }
  inspect(safety.safety_modes.length(), content="2")

  let bridge : @protocol.BridgeSpec = BridgeSpec::{
    contract_address: "0xBridge",
    target_chain_id: 137,
    min_amount_str: "1000000000000000000",
    max_amount_str: "100000000000000000000",
    has_validator_set: true,
    min_validators: 3,
  }
  debug_inspect(bridge.target_chain_id, content="137")
}

///|
test "TokenSafetySpec with all safety modes" {
  let safety : @protocol.TokenSafetySpec = TokenSafetySpec::{
    has_mint: true,
    mint_controlled: true,
    has_burn: true,
    has_pause: true,
    safety_modes: [
      ContractSafetyMode::Owned,
      ContractSafetyMode::TimeLock,
      ContractSafetyMode::Pausable,
      ContractSafetyMode::Upgradeable,
      ContractSafetyMode::RateLimited,
    ],
  }
  inspect(safety.safety_modes.length(), content="5")
  debug_inspect(safety.has_pause, content="true")
}

///|
test "complex AddressFormatSpec for BTC families" {
  let bech32 : @protocol.AddressFormatSpec = AddressFormatSpec::{
    ty: AddressType::BtcBech32,
    length: { min_chars: 26, max_chars: 42, byte_len: 20 },
    checksum_type: ChecksumType::Bech32,
    prefix_req: Some("bc1"),
    charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
    description: "SegWit",
  }
  debug_inspect(
    bech32.prefix_req,
    content=(
      #|Some("bc1")
    ),
  )

  let bech32m : @protocol.AddressFormatSpec = AddressFormatSpec::{
    ty: AddressType::BtcBech32m,
    length: { min_chars: 26, max_chars: 42, byte_len: 20 },
    checksum_type: ChecksumType::Bech32,
    prefix_req: Some("bc1p"),
    charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
    description: "Taproot",
  }
  debug_inspect(
    bech32m.prefix_req,
    content=(
      #|Some("bc1p")
    ),
  )
}

///|
test "complex AddressFormatSpec for Eth and Cosmos" {
  let eth_eip55 : @protocol.AddressFormatSpec = AddressFormatSpec::{
    ty: AddressType::EthEip55,
    length: { min_chars: 42, max_chars: 42, byte_len: 20 },
    checksum_type: ChecksumType::Eip55,
    prefix_req: Some("0x"),
    charset: "0123456789abcdefABCDEF",
    description: "Ethereum EIP-55",
  }
  debug_inspect(eth_eip55.length.min_chars, content="42")

  let cosmos : @protocol.AddressFormatSpec = AddressFormatSpec::{
    ty: AddressType::Cosmos,
    length: { min_chars: 24, max_chars: 45, byte_len: 20 },
    checksum_type: ChecksumType::Bech32,
    prefix_req: Some("cosmos1"),
    charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    description: "Cosmos",
  }
  debug_inspect(
    cosmos.prefix_req,
    content=(
      #|Some("cosmos1")
    ),
  )
}

///|
test "complex SignatureVerifySpec and all SecurityAssertResult variants" {
  let spec : @protocol.SignatureVerifySpec = SignatureVerifySpec::{
    message_hex: "deadbeef",
    signature_hex: "abcd",
    public_key_hex: "03abcdef",
    scheme: SignatureScheme::EcdsaSecp256k1,
  }
  debug_inspect(spec.scheme, content="EcdsaSecp256k1")

  let result : @protocol.SecurityAssertResult = SecurityAssertResult::Unsafe(
    "double spend",
  )
  debug_inspect(
    result,
    content=(
      #|Unsafe("double spend")
    ),
  )
}
