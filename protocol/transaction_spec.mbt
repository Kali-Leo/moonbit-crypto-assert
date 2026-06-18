///|
/// 交易状态枚举
pub(all) enum TxStatus {
  Pending
  Confirmed
  Failed
  Dropped
  Unknown
} derive(Debug, Eq)

///|
/// 交易输入的规约描述
pub(all) struct TxInputSpec {
  txid : String
  vout : UInt
  script_sig : String
  amount_str : String
} derive(Debug)

///|
/// 交易输出的规约描述
pub(all) struct TxOutputSpec {
  address : String
  amount_str : String
  script_pubkey : String
  is_change : Bool
} derive(Debug)

///|
/// 交易费用规约
pub(all) struct FeeSpec {
  rate_str : String
  total_str : String
  unit_desc : String
} derive(Debug)

///|
/// 完整交易规约
pub(all) struct TransactionSpec {
  version : UInt
  inputs : Array[TxInputSpec]
  outputs : Array[TxOutputSpec]
  locktime : UInt
  fee : FeeSpec
  txid : String
  sig_scheme : SignatureScheme
  signature_hex : String?
  public_key_hex : String?
} derive(Debug)

///|
/// 代币转账操作的规约
pub(all) struct TokenTransferSpec {
  from : String
  to : String
  contract : String
  amount_str : String
  chain_id : UInt
  precision : PrecisionSpec
} derive(Debug)

///|
/// 交易验证结果码
pub(all) enum TxValidationCode {
  Valid
  InvalidSignature
  InvalidInput
  InvalidOutput
  InsufficientFee
  DoubleSpend
  Expired
  AmountMismatch
  ChainIdMismatch
} derive(Debug, Eq)

///|
/// 签名验证请求的规约
pub(all) struct SignatureVerifySpec {
  message_hex : String
  signature_hex : String
  public_key_hex : String
  scheme : SignatureScheme
} derive(Debug)

///|
/// ═══════════════════════════════════════
/// 交易验证 Trait —— 编译期接口约束
/// 使用 self 参数确保编译期静态分发
/// ═══════════════════════════════════════
pub trait TransactionVerifier {
  fn validate_transaction(self : Self, TransactionSpec) -> TxValidationCode
  fn verify_signature(self : Self, SignatureVerifySpec) -> Bool
  fn compute_txid(self : Self, TransactionSpec) -> String
  fn estimate_fee(self : Self, TransactionSpec, String) -> FeeSpec
  fn validate_token_transfer(self : Self, TokenTransferSpec) -> TxValidationCode
}
