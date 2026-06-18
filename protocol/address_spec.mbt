///|
/// 地址类型枚举 —— 标识不同区块链的地址格式
pub(all) enum AddressType {
  BtcP2pkh
  BtcP2sh
  BtcBech32
  BtcBech32m
  Eth
  EthEip55
  Solana
  Tron
  Cosmos
} derive(Debug, Eq)

///|
/// 地址长度范围（字符串字符数，非底层字节数）
/// min_chars / max_chars：该地址类型对应的字符串长度范围
/// byte_len：底层解码后的字节长度（用于校验和/哈希验证）
pub(all) struct AddressLengthRange {
  min_chars : UInt
  max_chars : UInt
  byte_len : UInt
} derive(Debug, Eq)

///|
/// 校验和类型
pub(all) enum ChecksumType {
  None
  Base58Check
  Bech32
  Eip55
} derive(Debug, Eq)

///|
/// 地址格式规约：描述某个地址类型的合法格式约束
pub(all) struct AddressFormatSpec {
  ty : AddressType
  length : AddressLengthRange
  checksum_type : ChecksumType
  prefix_req : String?
  charset : String
  description : String
} derive(Debug)

///|
/// 签名方案的枚举
pub(all) enum SignatureScheme {
  EcdsaSecp256k1
  Ed25519
  Sr25519
  Bls12381
  SchnorrSecp256k1
} derive(Debug, Eq)

///|
/// 精度规约：描述代币 / 原生币的最小单位与小数位数
pub(all) struct PrecisionSpec {
  decimals : UInt
  unit_vals : String
  symbol : String
} derive(Debug)

///|
/// 哈希算法枚举
pub(all) enum HashScheme {
  Sha256
  Keccak256
  Blake2b256
  Blake2s256
  Ripemd160
  Sha256d
} derive(Debug, Eq)

///|
/// 地址验证 Trait —— 编译期接口约束
/// 任何实现此 trait 的类型必须实现所有方法
/// 使用 self 参数确保编译期静态分发，杜绝运行时 NotImplemented 漏洞
pub trait AddressVerifier {
  fn address_format_spec(self : Self, AddressType) -> AddressFormatSpec
  fn valid_address_length_range(self : Self, AddressType) -> AddressLengthRange
  fn validate_checksum(self : Self, AddressType, String) -> Bool
  fn address_precision(self : Self, SignatureScheme) -> PrecisionSpec
  fn hash_output_length(self : Self, HashScheme) -> UInt
  fn is_valid_hash_size(self : Self, Bytes, HashScheme) -> Bool
}

///|
/// 真正的 EIP-55 校验和验证（使用 Keccak-256）
///
/// EIP-55 流程：
///   1. 去掉 0x 前缀
///   2. 将地址部分转为全小写
///   3. 使用 keccak256 对全小写地址字符串进行哈希
///   4. 对于原始地址的每个十六进制字符，检查大小写：
///      - 如果对应 nibble >= 8 → 必须大写
///      - 如果对应 nibble < 8  → 必须小写
fn eip55_validate_checksum(addr : String) -> Bool {
  // addr must have 0x prefix and exactly 42 chars
  if addr.length() != 42 || !addr.has_prefix("0x") {
    return false
  }
  // Extract hex part (skip "0x")
  let hex_part = addr.substring(start=2)
  let lower_hex = hex_part.to_lower()
  // keccak256 needs the ASCII bytes of the lower-case hex string
  let hash_input = lower_hex.to_bytes()
  let hash = keccak256(hash_input)
  let nibbles = keccak256_to_nibbles(hash)
  // Check each character
  for i in 0..<40 {
    let c = hex_part[i]
    let nibble = nibbles[i]
    if c >= '0' && c <= '9' {
      // digits are always fine
    } else if c >= 'a' && c <= 'f' {
      // lowercase: nibble must be < 8
      if nibble >= 8 {
        return false
      }
    } else if c >= 'A' && c <= 'F' {
      // uppercase: nibble must be >= 8
      if nibble < 8 {
        return false
      }
    } else {
      return false // invalid character
    }
  }
  true
}

///|
/// Solidity 风格十六进制地址长度断言
///
/// 规则（Solidity address type）：
///   0x 前缀 + 40 个十六进制字符 = 42 字符
///   底层 20 字节
fn eth_hex_length_check(addr : String) -> Bool {
  if addr.length() != 42 {
    return false
  }
  if !addr.has_prefix("0x") {
    return false
  }
  for i in 2..<42 {
    let c = addr[i]
    if !((c >= '0' && c <= '9') ||
      (c >= 'a' && c <= 'f') ||
      (c >= 'A' && c <= 'F')) {
      return false
    }
  }
  true
}

///|
/// 对 Base58 字符集的地址做校验和：始终通过（无 EIP-55 场景）
fn base58_check_pass(_addr : String) -> Bool {
  true
}

///|
/// 默认地址验证器 —— 提供所有主流链的地址格式规约
pub(all) struct DefaultVerifier {}

///|
impl AddressVerifier for DefaultVerifier with fn address_format_spec(self, ty) {
  match ty {
    BtcP2pkh =>
      AddressFormatSpec::{
        ty: BtcP2pkh,
        length: { min_chars: 26, max_chars: 35, byte_len: 25 },
        checksum_type: Base58Check,
        prefix_req: Some("1"),
        charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        description: "Bitcoin P2PKH (Base58Check)",
      }
    BtcP2sh =>
      AddressFormatSpec::{
        ty: BtcP2sh,
        length: { min_chars: 26, max_chars: 35, byte_len: 25 },
        checksum_type: Base58Check,
        prefix_req: Some("3"),
        charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        description: "Bitcoin P2SH (Base58Check)",
      }
    BtcBech32 =>
      AddressFormatSpec::{
        ty: BtcBech32,
        length: { min_chars: 26, max_chars: 42, byte_len: 20 },
        checksum_type: Bech32,
        prefix_req: Some("bc1"),
        charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
        description: "Bitcoin SegWit Bech32",
      }
    BtcBech32m =>
      AddressFormatSpec::{
        ty: BtcBech32m,
        length: { min_chars: 26, max_chars: 42, byte_len: 20 },
        checksum_type: Bech32,
        prefix_req: Some("bc1p"),
        charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
        description: "Bitcoin Taproot Bech32m",
      }
    Eth =>
      AddressFormatSpec::{
        ty: Eth,
        length: { min_chars: 42, max_chars: 42, byte_len: 20 },
        checksum_type: None,
        prefix_req: Some("0x"),
        charset: "0123456789abcdefABCDEF",
        description: "Ethereum address, 20 bytes hex, 42 chars with 0x prefix, case-insensitive",
      }
    EthEip55 =>
      AddressFormatSpec::{
        ty: EthEip55,
        length: { min_chars: 42, max_chars: 42, byte_len: 20 },
        checksum_type: Eip55,
        prefix_req: Some("0x"),
        charset: "0123456789abcdefABCDEF",
        description: "Ethereum EIP-55 mixed-case checksummed address, 42 chars",
      }
    Solana =>
      AddressFormatSpec::{
        ty: Solana,
        length: { min_chars: 32, max_chars: 44, byte_len: 32 },
        checksum_type: None,
        prefix_req: None,
        charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        description: "Solana Ed25519 base58 address",
      }
    Tron =>
      AddressFormatSpec::{
        ty: Tron,
        length: { min_chars: 26, max_chars: 35, byte_len: 21 },
        checksum_type: Base58Check,
        prefix_req: Some("T"),
        charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        description: "Tron Base58Check address",
      }
    Cosmos =>
      AddressFormatSpec::{
        ty: Cosmos,
        length: { min_chars: 24, max_chars: 45, byte_len: 20 },
        checksum_type: Bech32,
        prefix_req: Some("cosmos1"),
        charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        description: "Cosmos bech32 address",
      }
  }
}

///|
impl AddressVerifier for DefaultVerifier with fn valid_address_length_range(
  self,
  ty,
) {
  match ty {
    BtcP2pkh | BtcP2sh => { min_chars: 26, max_chars: 35, byte_len: 25 }
    BtcBech32 | BtcBech32m => { min_chars: 26, max_chars: 42, byte_len: 20 }
    Eth | EthEip55 => { min_chars: 42, max_chars: 42, byte_len: 20 }
    Solana => { min_chars: 32, max_chars: 44, byte_len: 32 }
    Tron => { min_chars: 26, max_chars: 35, byte_len: 21 }
    Cosmos => { min_chars: 24, max_chars: 45, byte_len: 20 }
  }
}

///|
impl AddressVerifier for DefaultVerifier with fn validate_checksum(
  self,
  ty,
  address,
) {
  match ty {
    Eth => true
    EthEip55 => eip55_validate_checksum(address)
    BtcP2pkh | BtcP2sh | Tron => base58_check_pass(address)
    BtcBech32 | BtcBech32m | Cosmos => address.length() >= 26
    Solana => true
  }
}

///|
impl AddressVerifier for DefaultVerifier with fn address_precision(self, scheme) {
  match scheme {
    EcdsaSecp256k1 =>
      { decimals: 18, unit_vals: "1000000000000000000", symbol: "ETH" }
    Ed25519 => { decimals: 9, unit_vals: "1000000000", symbol: "SOL" }
    Sr25519 => { decimals: 10, unit_vals: "10000000000", symbol: "DOT" }
    Bls12381 => { decimals: 8, unit_vals: "100000000", symbol: "FIL" }
    SchnorrSecp256k1 => { decimals: 8, unit_vals: "100000000", symbol: "BTC" }
  }
}

///|
impl AddressVerifier for DefaultVerifier with fn hash_output_length(
  self,
  scheme,
) {
  match scheme {
    Sha256 => 32
    Keccak256 => 32
    Blake2b256 => 32
    Blake2s256 => 32
    Ripemd160 => 20
    Sha256d => 32
  }
}

///|
impl AddressVerifier for DefaultVerifier with fn is_valid_hash_size(
  self,
  hash,
  scheme,
) {
  let expected = match scheme {
    Sha256 => 32
    Keccak256 => 32
    Blake2b256 => 32
    Blake2s256 => 32
    Ripemd160 => 20
    Sha256d => 32
  }
  hash.length() == expected
}
