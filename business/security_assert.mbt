///|
/// 业务断言层 —— 安全检查断言
/// ═══════════════════════════════════════════
/// 使用泛型 + trait bound 进行编译期静态分发，杜绝运行时 NotImplemented 漏洞。
/// 所有业务断言都需要调用方注入一个具体的验证器实现。
/// ═══════════════════════════════════════════

///|
/// ═══════════════════════════════════════
/// 资金守恒断言（对接 Hermes 证明层）
/// ═══════════════════════════════════════

///|
/// 将 amount_str（十进制字符串）解析为 UInt64
/// 边解析边检查溢出，无法解析时抛出 NumericParseError
fn parse_amount(s : String) -> UInt64 raise @protocol.AssertError {
  let mut v : UInt64 = 0
  for c in s {
    if c < '0' || c > '9' {
      raise @protocol.AssertError::NumericParseError(
        "Invalid digit in amount: \{s}",
      )
    }
    let digit : UInt64 = (c.to_int() - '0'.to_int()).to_uint64()
    let next = v * 10 + digit
    if next < v {
      raise @protocol.AssertError::NumericParseError(
        "UInt64 overflow parsing amount: \{s}",
      )
    }
    v = next
  }
  if s.length() == 0 {
    raise @protocol.AssertError::NumericParseError("Empty amount string")
  }
  v
}

///|
/// 断言交易资金守恒：sum(inputs) == sum(outputs) + fee.total
///
/// 基于 `transfer_proof.mbtp` 中的形式化 lemma 和
/// `transfer_runtime.mbt` 中的运行时桥函数进行深度绑定。
///
/// 形式化验证链：
///   proof_require: fund_conservation_inv(total_in, total_out, fee)
///   proof_require: overflow_safe_lemma for each accumulation step
///   proof_ensure: check_transfer_correctness(total_in, total_out, fee)
///
/// 运行时通过 @protocol.check_overflow_safe 和
/// @protocol.check_fund_conservation 直接利用 lemma 桥函数。
pub fn assert_transaction_balance(
  tx : @protocol.TransactionSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  // 累加所有 inputs
  let mut total_in : UInt64 = 0
  for i in 0..<tx.inputs.length() {
    let amount = parse_amount(tx.inputs[i].amount_str)
    // overflow_safe_lemma: 利用 @protocol.check_overflow_safe 桥函数
    if !@protocol.check_overflow_safe(total_in, amount) {
      raise @protocol.AssertError::SecurityCheckFailed(
        "UInt64 overflow in total_in accumulation",
      )
    }
    total_in = total_in + amount
  }
  // 累加所有 outputs
  let mut total_out : UInt64 = 0
  for i in 0..<tx.outputs.length() {
    let amount = parse_amount(tx.outputs[i].amount_str)
    if !@protocol.check_overflow_safe(total_out, amount) {
      raise @protocol.AssertError::SecurityCheckFailed(
        "UInt64 overflow in total_out accumulation",
      )
    }
    total_out = total_out + amount
  }
  // 解析手续费
  let fee = parse_amount(tx.fee.total_str)
  // fee_nonnegative_lemma: UInt64 >= 0 天然满足

  // fund_conservation_inv + overflow_safe_lemma for out+fee:
  if !@protocol.check_fund_conservation(total_in, total_out, fee) {
    raise @protocol.AssertError::AmountImbalance(total_in, total_out, fee)
  }
  @protocol.AssertionResult::Valid
}

///|
/// ═══════════════════════════════════════
/// 协议层委托断言（SecurityVerifier trait）
/// ═══════════════════════════════════════
pub fn[V : @protocol.SecurityVerifier] assert_replay_protection(
  verifier : V,
  tx : @protocol.TransactionSpec,
  protection_spec : @protocol.ReplayProtectionSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_replay_protection(tx, protection_spec)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Replay warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Replay unsafe: \{msg}")
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_amount_in_range(
  verifier : V,
  amount_str : String,
  min_str : String,
  max_str : String,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.validate_amount_range(amount_str, min_str, max_str)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Amount warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Amount unsafe: \{msg}")
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_fee_within_ratio(
  verifier : V,
  fee_str : String,
  amount_str : String,
  max_ratio_str : String,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_fee_ratio(fee_str, amount_str, max_ratio_str)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Fee warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Fee unsafe: \{msg}")
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_contract_safety(
  verifier : V,
  spec : @protocol.TokenSafetySpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_contract_safety(spec)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed(
        "Contract warning: \{msg}",
      )
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed(
        "Contract unsafe: \{msg}",
      )
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_bridge_security(
  verifier : V,
  spec : @protocol.BridgeSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_bridge_security(spec)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Bridge warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Bridge unsafe: \{msg}")
  }
}
