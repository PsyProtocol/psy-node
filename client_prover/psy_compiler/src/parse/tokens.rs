use logos::Logos;

#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r]+")]
pub enum Token {
    // ─── Keywords ────────────────────────────────────────────────────────────
    #[token("const")]
    Const,
    #[token("let")]
    Let,
    #[token("pub")]
    Pub,
    #[token("struct")]
    Struct,
    #[token("impl")]
    Impl,
    #[token("fn")]
    Fn,
    #[token("if")]
    If,
    #[token("else")]
    Else,
    #[token("for")]
    For,
    #[token("in")]
    In,
    #[token("return")]
    Return,
    #[token("true")]
    True,
    #[token("false")]
    False,
    #[token("mut")]
    Mut,
    #[token("mod")]
    Mod,
    #[token("use")]
    Use,
    #[token("as")]
    As,
    #[token("trait")]
    Trait,
    #[token("where")]
    Where,
    #[token("while")]
    While,

    // ─── Type keywords ───────────────────────────────────────────────────────
    #[token("Felt")]
    Felt,
    #[token("Bool")]
    TBool,
    #[token("U32")]
    TU32,
    #[token("Hash")]
    THash,
    #[token("usize")]
    Usize,
    #[token("ContractStateArray")]
    ContractStateArray,
    #[token("ContractHashMap")]
    ContractHashMap,
    #[token("ChainContext")]
    ChainContext,
    #[token("Self")]
    SelfType,

    // ─── Identifiers and literals ────────────────────────────────────────────
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    Ident(String),

    #[regex(r"[0-9][0-9_]*", |lex| lex.slice().replace('_', "").parse::<u64>().ok())]
    IntLiteral(u64),

    #[regex(r#""[^"]*""#, |lex| {
        let s = lex.slice();
        s[1..s.len()-1].to_string()
    })]
    StringLiteral(String),

    // ─── Attributes ──────────────────────────────────────────────────────────
    #[token("#[derive(FeltSized)]")]
    DeriveFeltSized,
    #[token("#[contract]")]
    ContractAttr,
    #[token("#[contract_implementation]")]
    ContractImplAttr,
    #[token("#[contract_method]")]
    ContractMethodAttr,

    // ─── Operators ───────────────────────────────────────────────────────────
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("*")]
    Star,
    #[token("/")]
    Slash,
    #[token("%")]
    Percent,
    #[token("==")]
    EqEq,
    #[token("!=")]
    NotEq,
    #[token("<=")]
    LtEq,
    #[token(">=")]
    GtEq,
    #[token("&&")]
    AndAnd,
    #[token("||")]
    OrOr,
    #[token("<<")]
    Shl,
    #[token(">>")]
    Shr,
    #[token("!")]
    Bang,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("&")]
    Amp,
    #[token("|")]
    Pipe,
    #[token("^")]
    Caret,

    // ─── Assignment ──────────────────────────────────────────────────────────
    #[token("=")]
    Eq,
    #[token("+=")]
    PlusEq,
    #[token("-=")]
    MinusEq,
    #[token("*=")]
    StarEq,

    // ─── Delimiters ──────────────────────────────────────────────────────────
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,

    // ─── Punctuation ─────────────────────────────────────────────────────────
    #[token(",")]
    Comma,
    #[token(":")]
    Colon,
    #[token("::")]
    ColonColon,
    #[token(";")]
    Semi,
    #[token(".")]
    Dot,
    #[token("..")]
    DotDot,
    #[token("->")]
    Arrow,

    // ─── Comments ────────────────────────────────────────────────────────────
    #[regex(r"//[^\n]*\n?", |lex| lex.slice().to_string())]
    LineComment(String),

    // ─── Newline (tracked for span purposes) ─────────────────────────────────
    #[token("\n")]
    Newline,
}

impl Token {
    pub fn is_compound_assign(&self) -> bool {
        matches!(self, Token::PlusEq | Token::MinusEq | Token::StarEq)
    }

    pub fn compound_assign_op(&self) -> Option<super::ast::BinOp> {
        match self {
            Token::PlusEq => Some(super::ast::BinOp::Add),
            Token::MinusEq => Some(super::ast::BinOp::Sub),
            Token::StarEq => Some(super::ast::BinOp::Mul),
            _ => None,
        }
    }
}
