// 这个文件同时被 build.rs 和 lib.rs 用 include! 引入。
// 因此它只能用 core/std，不能 use 任何外部 crate，也不能声明 mod。

/// 每个部署阶段的 network magic。取值来自 psy_core/src/constants/protocol.rs：
/// MAINNET = 0x1337CF514544C069，TESTNET = 0x1337CF514544C169，REGTEST = 0x1337CF514544CF69。
///
/// testnet 在这里映射到 REGTEST 的值，因为现网就是用它跑起来的。
/// 要换成 0x1337CF514544C169 必须安排一次全新部署：magic 是电路常量，
/// 改它会改掉 UPS 电路指纹与 trust setup。
pub const STAGE_MAGICS: [(&str, u64); 3] = [
    ("localhost", 0x1337CF514544CF69),
    ("testnet", 0x1337CF514544CF69),
    ("mainnet", 0x1337CF514544C069),
];

/// 阶段名对应的 magic；阶段名不认识就返回 None。
pub fn magic_for_stage(stage: &str) -> Option<u64> {
    let mut i = 0;
    while i < STAGE_MAGICS.len() {
        if STAGE_MAGICS[i].0 == stage {
            return Some(STAGE_MAGICS[i].1);
        }
        i += 1;
    }
    None
}

/// 解析配置里的 magic 字符串，接受带不带 0x 前缀两种写法。
pub fn parse_magic_hex(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if body.is_empty() {
        return Err("magic must not be empty".to_string());
    }
    u64::from_str_radix(body, 16).map_err(|e| format!("invalid magic {raw}: {e}"))
}

/// 人类可读的阶段列表，用在报错信息里。
pub fn known_stages() -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < STAGE_MAGICS.len() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(STAGE_MAGICS[i].0);
        i += 1;
    }
    out
}
