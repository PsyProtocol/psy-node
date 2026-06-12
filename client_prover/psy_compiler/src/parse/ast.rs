use std::fmt;

/// A complete PSY program (one source file).
#[derive(Debug, Clone)]
pub struct Program {
    pub items: Vec<Item>,
}

/// Top-level item in a PSY source file.
#[derive(Debug, Clone)]
pub enum Item {
    ConstDecl(ConstDecl),
    StructDef(StructDef),
    ContractDef(ContractDef),
    ImplBlock(ImplBlock),
    TraitDef(TraitDef),
    TraitImplBlock(TraitImplBlock),
    ModDecl(ModDecl),
    UseDecl(UseDecl),
}

/// `[pub] mod name;` — module declaration (loads external file)
#[derive(Debug, Clone)]
pub struct ModDecl {
    pub name: String,
    pub is_public: bool,
    pub span: Span,
}

/// `use path::to::item;` or `use path::to::*;` — import declaration
#[derive(Debug, Clone)]
pub struct UseDecl {
    /// Path segments, e.g., `["helpers", "math", "max"]`
    pub path: Vec<String>,
    /// True for `use foo::*` glob imports
    pub is_glob: bool,
    /// Optional alias for `use foo as bar`
    pub alias: Option<String>,
    pub span: Span,
}

/// Module path type alias
pub type ModulePath = Vec<String>;

/// `const NAME: Type = value;`
#[derive(Debug, Clone)]
pub struct ConstDecl {
    pub name: String,
    pub ty: Type,
    pub value: Expr,
    pub span: Span,
}

/// `#[derive(FeltSized)] pub struct Name { fields }`
#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
    pub derives: Vec<String>,
    pub span: Span,
}

/// `#[contract] pub struct Name { fields }`
#[derive(Debug, Clone)]
pub struct ContractDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
    pub span: Span,
}

/// `#[contract_implementation] impl Name { methods }`
#[derive(Debug, Clone)]
pub struct ImplBlock {
    pub contract_name: String,
    pub methods: Vec<MethodDef>,
    pub span: Span,
}

/// `[pub] trait Name { fn method_name(&self, ...) -> ReturnType; ... }`
#[derive(Debug, Clone)]
pub struct TraitDef {
    pub name: String,
    pub is_public: bool,
    pub methods: Vec<TraitMethodDef>,
    pub span: Span,
}

/// A method signature within a trait definition.
#[derive(Debug, Clone)]
pub struct TraitMethodDef {
    pub name: String,
    pub params: Vec<ParamDef>,
    pub return_type: Option<Type>,
    /// If Some, this method has a default implementation body.
    pub default_body: Option<Vec<Stmt>>,
    pub span: Span,
}

/// `impl TraitName for StructName { methods }`
#[derive(Debug, Clone)]
pub struct TraitImplBlock {
    pub trait_name: String,
    pub target_name: String,
    pub methods: Vec<MethodDef>,
    pub span: Span,
}

/// A struct or contract field.
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub ty: Type,
    pub is_pub: bool,
    pub comment: Option<String>,
    pub span: Span,
}

/// A method definition within an impl block.
#[derive(Debug, Clone)]
pub struct MethodDef {
    pub name: String,
    pub is_pub: bool,
    pub is_contract_method: bool,
    pub generics: Vec<ConstGenericParam>,
    pub params: Vec<ParamDef>,
    pub return_type: Option<Type>,
    pub body: Vec<Stmt>,
    pub span: Span,
}

/// A const generic parameter: `<const N: usize>`
#[derive(Debug, Clone)]
pub struct ConstGenericParam {
    pub name: String,
    pub ty: Type,
    pub span: Span,
}

/// A function parameter.
#[derive(Debug, Clone)]
pub struct ParamDef {
    pub name: String,
    pub ty: ParamType,
    pub span: Span,
}

/// Parameter type — can be by-value or by-reference.
#[derive(Debug, Clone)]
pub enum ParamType {
    SelfRef { mutable: bool },
    Typed { ty: Type, is_ref: bool, mutable: bool },
}

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// `Felt`, `Bool`, `U32`, `Hash`
    Primitive(PrimitiveType),
    /// `[T; N]`
    Array(Box<Type>, ArrayLen),
    /// `ContractStateArray<N, T>`
    ContractStateArray { count: ArrayLen, element_type: Box<Type> },
    /// `ContractHashMap<K, V, CAP>` — indexed merkle tree map with K keys and V
    /// values
    ContractHashMap {
        key_type: Box<Type>,
        value_type: Box<Type>,
        capacity: ArrayLen,
    },
    /// User-defined struct name
    Named(String),
    /// `usize` (only for const declarations)
    Usize,
    /// `&T` or `&mut T`
    Ref { inner: Box<Type>, mutable: bool },
    /// `&'static SomeABI` (compile-time ABI reference)
    StaticRef(Box<Type>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrimitiveType {
    Felt,
    Bool,
    U32,
    Hash,
}

/// Array length — either a literal or a named constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArrayLen {
    Literal(usize),
    Named(String),
}

// ─── Statements ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Stmt {
    /// `let name: ty = value;` or `let name = value;`
    Let {
        name: String,
        ty: Option<Type>,
        value: Expr,
        span: Span,
    },
    /// `target = value;`
    Assign { target: Expr, value: Expr, span: Span },
    /// `target += value;` etc.
    CompoundAssign { target: Expr, op: BinOp, value: Expr, span: Span },
    /// Expression statement (e.g., function call)
    Expr(Expr),
    /// `if cond { ... } else if cond { ... } else { ... }`
    If {
        condition: Expr,
        then_block: Vec<Stmt>,
        else_if_blocks: Vec<(Expr, Vec<Stmt>)>,
        else_block: Option<Vec<Stmt>>,
        span: Span,
    },
    /// `for var in start..end { ... }`
    For {
        var: String,
        start: Expr,
        end: Expr,
        body: Vec<Stmt>,
        span: Span,
    },
    /// `while cond { ... }`
    While { condition: Expr, body: Vec<Stmt>, span: Span },
    /// `return expr;` or `return;`
    Return { value: Option<Expr>, span: Span },
}

// ─── Expressions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Expr {
    /// Integer literal
    IntLiteral(u64, Span),
    /// Boolean literal
    BoolLiteral(bool, Span),
    /// String literal (only used in require messages)
    StringLiteral(String, Span),
    /// Variable / constant name
    Ident(String, Span),
    /// `expr.field`
    FieldAccess(Box<Expr>, String, Span),
    /// `expr[index]`
    IndexAccess(Box<Expr>, Box<Expr>, Span),
    /// `a + b`, `a >= b`, etc.
    BinaryOp(Box<Expr>, BinOp, Box<Expr>, Span),
    /// `!a`, `-a`
    UnaryOp(UnaryOp, Box<Expr>, Span),
    /// `expr.method(args)`
    MethodCall {
        receiver: Box<Expr>,
        method: String,
        args: Vec<Expr>,
        span: Span,
    },
    /// `func(args)`
    FunctionCall { name: String, args: Vec<Expr>, span: Span },
    /// `[a, b, c]`
    ArrayLiteral(Vec<Expr>, Span),
    /// `StructName { field: value, ... }`
    StructLiteral { name: String, fields: Vec<(String, Expr)>, span: Span },
    /// `expr.contract_state::<ABI>(contract_id)` — typed cross-contract access
    TypedContractAccess {
        /// The user accessor expression, e.g. `ctx.users[sender]`
        user_expr: Box<Expr>,
        /// The ABI type name, e.g. `Self` or `OtherContract`
        abi_type: String,
        /// The contract ID expression
        contract_id: Box<Expr>,
        /// Chained field/index accesses after the contract_state call
        access_chain: Vec<AccessStep>,
        span: Span,
    },
}

/// A step in a chained access path (field or index).
#[derive(Debug, Clone)]
pub enum AccessStep {
    Field(String),
    Index(Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

// ─── Span ────────────────────────────────────────────────────────────────────

/// Source location for error reporting.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn merge(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

// ─── Helper impls ────────────────────────────────────────────────────────────

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::IntLiteral(_, s) => *s,
            Expr::BoolLiteral(_, s) => *s,
            Expr::StringLiteral(_, s) => *s,
            Expr::Ident(_, s) => *s,
            Expr::FieldAccess(_, _, s) => *s,
            Expr::IndexAccess(_, _, s) => *s,
            Expr::BinaryOp(_, _, _, s) => *s,
            Expr::UnaryOp(_, _, s) => *s,
            Expr::MethodCall { span, .. } => *span,
            Expr::FunctionCall { span, .. } => *span,
            Expr::ArrayLiteral(_, s) => *s,
            Expr::StructLiteral { span, .. } => *span,
            Expr::TypedContractAccess { span, .. } => *span,
        }
    }
}

impl fmt::Display for PrimitiveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimitiveType::Felt => write!(f, "Felt"),
            PrimitiveType::Bool => write!(f, "Bool"),
            PrimitiveType::U32 => write!(f, "U32"),
            PrimitiveType::Hash => write!(f, "Hash"),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Primitive(p) => write!(f, "{}", p),
            Type::Array(inner, len) => write!(f, "[{}; {}]", inner, len),
            Type::ContractStateArray { count, element_type } => {
                write!(f, "ContractStateArray<{}, {}>", count, element_type)
            }
            Type::ContractHashMap {
                key_type,
                value_type,
                capacity,
            } => {
                write!(f, "ContractHashMap<{}, {}, {}>", key_type, value_type, capacity)
            }
            Type::Named(name) => write!(f, "{}", name),
            Type::Usize => write!(f, "usize"),
            Type::Ref { inner, mutable } => {
                if *mutable {
                    write!(f, "&mut {}", inner)
                } else {
                    write!(f, "&{}", inner)
                }
            }
            Type::StaticRef(inner) => write!(f, "&'static {}", inner),
        }
    }
}

impl fmt::Display for ArrayLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArrayLen::Literal(n) => write!(f, "{}", n),
            ArrayLen::Named(name) => write!(f, "{}", name),
        }
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Mod => "%",
            BinOp::Eq => "==",
            BinOp::Neq => "!=",
            BinOp::Lt => "<",
            BinOp::Lte => "<=",
            BinOp::Gt => ">",
            BinOp::Gte => ">=",
            BinOp::And => "&&",
            BinOp::Or => "||",
            BinOp::BitAnd => "&",
            BinOp::BitOr => "|",
            BinOp::BitXor => "^",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
        };
        write!(f, "{}", s)
    }
}
