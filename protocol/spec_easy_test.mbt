///|
/// 规约层 —— 基础测试（黑盒测试）
/// 测试所有规约类型的构造、枚举值、以及结构体字段
/// ═══════════════════════════════════════════

///|
test "AddressType enum values are consistent" {
  let addr_types : Array[@protocol.AddressType] = [
    AddressType::BtcP2pkh,
    AddressType::BtcP2sh,
    AddressType::BtcBech32,
    AddressType::BtcBech32m,
    AddressType::Eth,
    AddressType::EthEip55,
    AddressType::Solana,
    AddressType::Tron,
    AddressType::Cosmos,
  ]
  inspect(addr_types.length(), content="9")
}

///|
test "SignatureScheme enum values" {
  let schemes : Array[@protocol.SignatureScheme] = [
    SignatureScheme::EcdsaSecp256k1,
    SignatureScheme::Ed25519,
    SignatureScheme::Sr25519,
    SignatureScheme::Bls12381,
    SignatureScheme::SchnorrSecp256k1,
  ]
  inspect(schemes.length(), content="5")
}

///|
test "HashScheme enum values" {
  let schemes : Array[@protocol.HashScheme] = [
    HashScheme::Sha256,
    HashScheme::Keccak256,
    HashScheme::Blake2b256,
    HashScheme::Blake2s256,
    HashScheme::Ripemd160,
    HashScheme::Sha256d,
  ]
  inspect(schemes.length(), content="6")
}

///|
test "AddressFormatSpec construction" {
  let spec : @protocol.AddressFormatSpec = AddressFormatSpec::{
    ty: AddressType::Eth,
    length: { min_chars: 42, max_chars: 42, byte_len: 20 },
    checksum_type: ChecksumType::None,
    prefix_req: Some("0x"),
    charset: "0123456789abcdef",
    description: "Ethereum",
  }
  debug_inspect(spec.ty, content="Eth")
  debug_inspect(spec.length.min_chars, content="42")
  debug_inspect(spec.checksum_type, content="None")
}

///|
test "TransactionSpec construction and TxValidationCode" {
  let fee : @protocol.FeeSpec = FeeSpec::{
    rate_str: "10",
    total_str: "5000",
    unit_desc: "sat/vB",
  }
  let input : @protocol.TxInputSpec = TxInputSpec::{
    txid: "abc123",
    vout: 0,
    script_sig: "sig",
    amount_str: "100000",
  }
  let output : @protocol.TxOutputSpec = TxOutputSpec::{
    address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    amount_str: "90000",
    script_pubkey: "pubkey",
    is_change: false,
  }
  let tx : @protocol.TransactionSpec = TransactionSpec::{
    version: 1,
    inputs: [input],
    outputs: [output],
    locktime: 0,
    fee,
    txid: "txid123",
    sig_scheme: SignatureScheme::EcdsaSecp256k1,
    signature_hex: None,
    public_key_hex: None,
  }
  debug_inspect(tx.version, content="1")
  inspect(tx.inputs.length(), content="1")
  debug_inspect(tx.sig_scheme, content="EcdsaSecp256k1")
}

///|
test "SecurityAssertResult values" {
  let safe : @protocol.SecurityAssertResult = SecurityAssertResult::Safe
  let warning : @protocol.SecurityAssertResult = SecurityAssertResult::Warning(
    "high slippage",
  )
  let unsafe_val : @protocol.SecurityAssertResult = SecurityAssertResult::Unsafe(
    "reentrancy detected",
  )
  debug_inspect(safe, content="Safe")
  debug_inspect(
    warning,
    content=(
      #|Warning("high slippage")
    ),
  )
  debug_inspect(
    unsafe_val,
    content=(
      #|Unsafe("reentrancy detected")
    ),
  )
}

///|
test "ContractSafetyMode enumeration" {
  let modes : Array[@protocol.ContractSafetyMode] = [
    ContractSafetyMode::Owned,
    ContractSafetyMode::TimeLock,
    ContractSafetyMode::Pausable,
    ContractSafetyMode::Upgradeable,
    ContractSafetyMode::RateLimited,
  ]
  inspect(modes.length(), content="5")
}

///|
test "PrecisionSpec and TxValidationCode" {
  let eth_precision : @protocol.PrecisionSpec = PrecisionSpec::{
    decimals: 18,
    unit_vals: "1000000000000000000",
    symbol: "ETH",
  }
  debug_inspect(eth_precision.decimals, content="18")

  let code : @protocol.TxValidationCode = TxValidationCode::Valid
  debug_inspect(code, content="Valid")
}
