///|
/// 安全断言结果
pub(all) enum SecurityAssertResult {
  Safe
  Warning(String)
  Unsafe(String)
} derive(Debug, Eq)

///|
/// 防重放攻击规约
pub(all) struct ReplayProtectionSpec {
  require_nonce : Bool
  require_chain_id : Bool
  require_timestamp : Bool
  max_nonce_reuse : UInt
} derive(Debug)

///|
/// 合约安全模式枚举
pub(all) enum ContractSafetyMode {
  Owned
  TimeLock
  Pausable
  Upgradeable
  RateLimited
} derive(Debug, Eq)

///|
/// 代币安全规约
pub(all) struct TokenSafetySpec {
  has_mint : Bool
  mint_controlled : Bool
  has_burn : Bool
  has_pause : Bool
  safety_modes : Array[ContractSafetyMode]
} derive(Debug)

///|
/// 跨链桥接规约
pub(all) struct BridgeSpec {
  contract_address : String
  target_chain_id : UInt
  min_amount_str : String
  max_amount_str : String
  has_validator_set : Bool
  min_validators : UInt
} derive(Debug)

///|
/// ═══════════════════════════════════════
/// 安全验证 Trait —— 编译期接口约束
/// 使用 self 参数确保编译期静态分发，杜绝运行时 NotImplemented 漏洞
/// ═══════════════════════════════════════
pub trait SecurityVerifier {
  fn check_replay_protection(self : Self, TransactionSpec, ReplayProtectionSpec) -> SecurityAssertResult
  fn check_contract_safety(self : Self, TokenSafetySpec) -> SecurityAssertResult
  fn check_bridge_security(self : Self, BridgeSpec) -> SecurityAssertResult
  fn validate_amount_range(self : Self, String, String, String) -> SecurityAssertResult
  fn check_fee_ratio(self : Self, String, String, String) -> SecurityAssertResult
}
