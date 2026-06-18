///|
/// 断言结果：成功
pub(all) enum AssertionResult {
  Valid
} derive(Debug, Eq)

///|
/// 断言错误类型 —— 当断言失败时抛出的详细错误
/// 注意：智能合约环境下不应有 NotImplemented；
/// 所有错误必须是可验证的密码学/业务错误。
pub(all) suberror AssertError {
  InvalidPrefix(String, String)
  InvalidLength(String, UInt, UInt)
  InvalidCharacter(String, Char)
  ChecksumMismatch(String)
  AmountImbalance(UInt64, UInt64, UInt64)
  IncompatibleScheme(SignatureScheme, AddressType)
  SignatureVerificationFailed(String)
  NumericParseError(String)
  HashLengthMismatch(UInt, UInt)
  SecurityCheckFailed(String)
} derive(Debug)
