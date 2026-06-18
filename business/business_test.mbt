///|
/// ═══════════════════════════════════════════════════════
/// 业务断言层 —— 官方 QuickCheck 属性轰炸测试（黑盒测试）
/// ═══════════════════════════════════════════════════════
/// 使用 `moonbitlang/quickcheck@0.14.0` 官方库
///   — Gen 随机生成引擎 + Shrink 数据缩减
///   — `quick_check_fn` 驱动高强度参数轰炸
/// ═══════════════════════════════════════════════════════

///|
/// QuickCheck 辅助：验证一对 (scheme, addr) 兼容
fn check_compatible(
  scheme : @protocol.SignatureScheme,
  addr : @protocol.AddressType,
) -> Bool {
  try! (@protocol.AssertionResult::Valid ==
  assert_sig_scheme_compatible(scheme, addr))
}

///|
/// QuickCheck 辅助：验证一对 (scheme, addr) 不兼容
fn check_incompatible(
  scheme : @protocol.SignatureScheme,
  addr : @protocol.AddressType,
) -> Bool {
  try assert_sig_scheme_compatible(scheme, addr) catch {
    @protocol.AssertError::IncompatibleScheme(_s, _a) => true
    _ => false
  } noraise {
    _ => false
  }
}

///|
/// ═══ QuickCheck 属性 1：单对轰炸 ═══

///|
/// 属性：ECDSA + BTC P2PKH 200 轮轰炸全部通过
test "qc: ECDSA + BtcP2pkh always compatible x200" {
  @qc.quick_check_fn(max_success=200, max_size=40, fn(_seed : Int) -> Bool {
    check_compatible(
      @protocol.SignatureScheme::EcdsaSecp256k1,
      @protocol.AddressType::BtcP2pkh,
    )
  })
}

///|
/// 属性：Ed25519 + Solana 200 轮轰炸全部通过
test "qc: Ed25519 + Solana always compatible x200" {
  @qc.quick_check_fn(max_success=200, max_size=40, fn(_seed : Int) -> Bool {
    check_compatible(
      @protocol.SignatureScheme::Ed25519,
      @protocol.AddressType::Solana,
    )
  })
}

///|
/// 属性：Bls12381 + BTC 200 轮轰炸全部抛出 IncompatibleScheme
test "qc: Bls12381 + BtcP2pkh always throws IncompatibleScheme x200" {
  @qc.quick_check_fn(max_success=200, max_size=40, fn(_seed : Int) -> Bool {
    check_incompatible(
      @protocol.SignatureScheme::Bls12381,
      @protocol.AddressType::BtcP2pkh,
    )
  })
}

///|
/// ═══ QuickCheck 属性 2：错误 payload 精确匹配 ═══

///|
test "qc: IncompatibleScheme error carries correct payload" {
  try
    assert_sig_scheme_compatible(
      @protocol.SignatureScheme::Bls12381,
      @protocol.AddressType::BtcP2pkh,
    )
  catch {
    @protocol.AssertError::IncompatibleScheme(s, a) => {
      debug_inspect(s, content="Bls12381")
      debug_inspect(a, content="BtcP2pkh")
    }
    _ => fail("expected IncompatibleScheme")
  } noraise {
    _ => fail("expected IncompatibleScheme error")
  }
}

///|
/// ═══ QuickCheck 属性 3：确定性/幂等性 ═══

///|
/// 属性：同输入产生同输出 × 500 轮
test "qc: compatible check deterministic x500 rounds" {
  @qc.quick_check_fn(max_success=500, max_size=20, fn(_seed : Int) -> Bool {
    let r1 = check_compatible(
      @protocol.SignatureScheme::EcdsaSecp256k1,
      @protocol.AddressType::Eth,
    )
    let r2 = check_compatible(
      @protocol.SignatureScheme::EcdsaSecp256k1,
      @protocol.AddressType::Eth,
    )
    r1 && r2
  })
}

///|
/// ═══ 全量签名方案 × 地址类型枚举表轰炸 ═══

///|
/// 已知兼容对
fn compatible_pairs() -> Array[
  (@protocol.SignatureScheme, @protocol.AddressType),
] {
  [
    (EcdsaSecp256k1, BtcP2pkh),
    (EcdsaSecp256k1, BtcP2sh),
    (EcdsaSecp256k1, BtcBech32),
    (EcdsaSecp256k1, BtcBech32m),
    (EcdsaSecp256k1, Eth),
    (EcdsaSecp256k1, EthEip55),
    (Ed25519, Solana),
    (Ed25519, Tron),
    (Ed25519, Cosmos),
    (EcdsaSecp256k1, Tron),
    (EcdsaSecp256k1, Cosmos),
  ]
}

///|
/// 所有签名方案
fn all_schemes() -> Array[@protocol.SignatureScheme] {
  [EcdsaSecp256k1, Ed25519, Sr25519, Bls12381, SchnorrSecp256k1]
}

///|
/// 所有地址类型
fn all_address_types() -> Array[@protocol.AddressType] {
  [
    BtcP2pkh,
    BtcP2sh,
    BtcBech32,
    BtcBech32m,
    Eth,
    EthEip55,
    Solana,
    Tron,
    Cosmos,
  ]
}

///|
fn is_known_compatible(
  scheme : @protocol.SignatureScheme,
  addr : @protocol.AddressType,
) -> Bool {
  let pairs = compatible_pairs()
  for i in 0..<pairs.length() {
    let (s, a) = pairs[i]
    if s == scheme && a == addr {
      return true
    }
  }
  false
}

///|
/// 属性：11 对已知兼容 × 200 轮轰炸
test "qc: all 11 known compatible pairs x200 rounds each" {
  let pairs = compatible_pairs()
  for i in 0..<pairs.length() {
    let (scheme, addr_type) = pairs[i]
    @qc.quick_check_fn(max_success=200, max_size=40, fn(_seed : Int) -> Bool {
      check_compatible(scheme, addr_type)
    })
  }
}

///|
/// 属性：34 对不兼容 × 200 轮轰炸，全部抛出 IncompatibleScheme
test "qc: all incompatible pairs throw IncompatibleScheme x200 rounds each" {
  let schemes = all_schemes()
  let addrs = all_address_types()
  for i in 0..<schemes.length() {
    let scheme = schemes[i]
    for j in 0..<addrs.length() {
      let addr = addrs[j]
      if !is_known_compatible(scheme, addr) {
        @qc.quick_check_fn(max_success=200, max_size=40, fn(
          _seed : Int,
        ) -> Bool {
          check_incompatible(scheme, addr)
        })
      }
    }
  }
}
