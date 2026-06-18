///|
/// ═══════════════════════════════════════════════════════
/// 转账运行时验证桥（Lemma → Runtime Bridge）
/// ═══════════════════════════════════════════════════════
/// 本文件将 transfer_proof.mbtp 中的形式化 lemma 映射为
/// 运行时可调用的验证函数。每个函数：
///
///   1. 实现与对应 lemma 完全等价的运行时检查逻辑
///   2. 在 docstring 中引用对应的 lemma 名称作为 proof_require
///   3. 提供 overflow_safe_lemma 风格的溢出防护
///
/// 使用者应通过这些桥函数进行业务断言，而非手工编写溢出检查。
/// 编译器将在 .mbtp 层验证 lemma，运行时由桥函数执行一致性检查。
/// ═══════════════════════════════════════════════════════

///|
/// Runtime bridge for `fund_conservation_inv`
///
/// proof_require: fund_conservation_inv(total_in, total_out, fee)
///   from transfer_proof.mbtp
///
/// 验证：total_in == total_out + fee（资金守恒）
/// 使用 overflow_safe_lemma 确保 total_out + fee 不溢出。
pub fn check_fund_conservation(
  total_in : UInt64,
  total_out : UInt64,
  fee : UInt64,
) -> Bool {
  // overflow_safe_lemma: 检查 total_out + fee >= total_out（无回绕）
  let sum_out_fee = total_out + fee
  if sum_out_fee < total_out {
    return false // overflow detected
  }
  total_in == sum_out_fee
}

///|
/// Runtime bridge for `overflow_safe_lemma`
///
/// proof_require: overflow_safe_lemma(a, b)
///   from transfer_proof.mbtp
///
/// 验证：a + b 不会发生 UInt64 回绕（即 a + b >= a 且 a + b >= b）
pub fn check_overflow_safe(a : UInt64, b : UInt64) -> Bool {
  let sum = a + b
  sum >= a && sum >= b
}

///|
/// Runtime bridge for `no_inflation_lemma`
///
/// proof_require: no_inflation_lemma(total_in, total_out, fee)
///   from transfer_proof.mbtp
///
/// 验证：total_in >= total_out（无通胀），
/// 前提是 fund_conservation_inv 成立且 fee >= 0。
pub fn check_no_inflation(
  total_in : UInt64,
  total_out : UInt64,
  fee : UInt64,
) -> Bool {
  // Step (1): fund_conservation_inv → in == out + fee
  if !check_fund_conservation(total_in, total_out, fee) {
    return false
  }
  // Step (2): fee_nonnegative_lemma → fee >= 0 (UInt64 天生满足)
  // Step (3)-(4): in >= out
  total_in >= total_out
}

///|
/// Runtime bridge for `fee_nonnegative_lemma`
///
/// proof_require: fee_nonnegative_lemma(fee)
///   from transfer_proof.mbtp
///
/// UInt64 天生非负，此函数为显式桥接存在。
pub fn check_fee_nonnegative(fee : UInt64) -> Bool {
  // UInt64 >= 0 总是成立
  true
}

///|
/// Runtime bridge for `value_monotonic_lemma`
///
/// proof_require: value_monotonic_lemma(in1, in2, out, fee)
///   from transfer_proof.mbtp
///
/// 如果 in1 >= in2，且两者都 >= out + fee，
/// 则 (in1 - out - fee) >= (in2 - out - fee)。
pub fn check_value_monotonic(
  in1 : UInt64,
  in2 : UInt64,
  out : UInt64,
  fee : UInt64,
) -> Bool {
  // precondition 检查
  if in1 < in2 {
    return false
  }
  let out_fee = out + fee
  if out_fee < out {
    return false // overflow
  }
  if in1 < out_fee {
    return false
  }
  if in2 < out_fee {
    return false
  }
  // postcondition: (in1 - out - fee) >= (in2 - out - fee)
  in1 - out_fee >= in2 - out_fee
}

///|
/// Runtime bridge for `transfer_state_invariant`
///
/// proof_require: transfer_state_invariant(pre_total, post_total)
///   from transfer_proof.mbtp
///
/// 转账前后系统总资产守恒：pre_total == post_total
pub fn check_transfer_state_invariant(
  pre_total : UInt64,
  post_total : UInt64,
) -> Bool {
  pre_total == post_total
}

///|
/// Runtime bridge for `transfer_correctness_theorem`
///
/// proof_require: transfer_correctness_theorem(total_in, total_out, fee)
///   from transfer_proof.mbtp
///
/// 综合定理：如果 funds_conservation_inv 和 fee >= 0 成立，
/// 则 (a) no_inflation (b) transfer_state_invariant (c) 输出非负。
pub fn check_transfer_correctness(
  total_in : UInt64,
  total_out : UInt64,
  fee : UInt64,
) -> Bool {
  if !check_no_inflation(total_in, total_out, fee) {
    return false
  }
  if !check_transfer_state_invariant(total_in, total_out + fee) {
    return false
  }
  true
}

///|
/// ═══════════════════════════════════════
/// 复合验证器：在单次调用中执行全链路检查
/// ═══════════════════════════════════════

///|
/// 全链路转账验证：
///
///   (1) 每个输入金额的累加不溢出（overflow_safe_lemma）
///   (2) 每个输出金额的累加不溢出
///   (3) 手续费 + 输出不溢出
///   (4) total_in == total_out + fee（fund_conservation_inv）
///
/// 调用此函数等价于在运行时执行 transfer_correctness_theorem 的
/// 全部前提检查。
///
/// proof_require: transfer_correctness_theorem(total_in, total_out, fee)
/// proof_require: overflow_safe_lemma for each accumulation step
pub fn verify_transfer_balance_chain(
  input_amounts : FixedArray[UInt64],
  output_amounts : FixedArray[UInt64],
  fee : UInt64,
) -> Bool {
  // (1) 累加输入
  let mut total_in : UInt64 = 0
  for i in 0..<input_amounts.length() {
    let next = total_in + input_amounts[i]
    if next < total_in {
      return false // overflow_safe_lemma violation
    }
    total_in = next
  }
  // (2) 累加输出
  let mut total_out : UInt64 = 0
  for i in 0..<output_amounts.length() {
    let next = total_out + output_amounts[i]
    if next < total_out {
      return false // overflow_safe_lemma violation
    }
    total_out = next
  }
  // (3) out + fee 溢出检查
  let out_fee = total_out + fee
  if out_fee < total_out {
    return false
  }
  // (4) fund_conservation_inv
  total_in == out_fee
}
