use anyhow::{bail, Result};
use logos::Logos;

use super::{ast::*, tokens::Token};

/// Spanned token: (token, byte_start, byte_end)
type SpannedToken = (Token, usize, usize);

pub struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
}

impl Parser {
    pub fn new(source: &str) -> Self {
        let mut tokens = Vec::new();
        let lexer = Token::lexer(source);
        for (result, span) in lexer.spanned() {
            match result {
                Ok(tok) => {
                    // Skip comments and newlines
                    if !matches!(tok, Token::LineComment(_) | Token::Newline) {
                        tokens.push((tok, span.start, span.end));
                    }
                }
                Err(_) => {
                    // Skip unrecognized tokens (will be caught as parse errors)
                }
            }
        }
        Parser { tokens, pos: 0 }
    }

    // ─── Token helpers ───────────────────────────────────────────────────────

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(t, _, _)| t)
    }

    fn peek_span(&self) -> Span {
        self.tokens.get(self.pos).map(|(_, s, e)| Span::new(*s, *e)).unwrap_or_default()
    }

    fn advance(&mut self) -> Option<SpannedToken> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<Span> {
        match self.advance() {
            Some((ref tok, s, e)) if tok == expected => Ok(Span::new(s, e)),
            Some((tok, s, _)) => bail!("Expected {:?}, got {:?} at offset {}", expected, tok, s),
            None => bail!("Expected {:?}, got EOF", expected),
        }
    }

    fn expect_ident(&mut self) -> Result<(String, Span)> {
        match self.advance() {
            Some((Token::Ident(name), s, e)) => Ok((name, Span::new(s, e))),
            // Also allow type keywords used as identifiers in certain contexts
            Some((Token::SelfType, s, e)) => Ok(("Self".to_string(), Span::new(s, e))),
            Some((tok, s, _)) => bail!("Expected identifier, got {:?} at offset {}", tok, s),
            None => bail!("Expected identifier, got EOF"),
        }
    }

    fn at(&self, expected: &Token) -> bool {
        self.peek() == Some(expected)
    }

    fn eat(&mut self, expected: &Token) -> bool {
        if self.at(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    /// Look ahead past `{` to determine if this is a struct literal.
    /// A struct literal has the pattern `{ ident: ... }` or `{ }`.
    /// This avoids misinterpreting `N { statements... }` as a struct literal
    /// when an uppercase identifier (e.g. a const generic) precedes a block.
    fn is_struct_literal_ahead(&self) -> bool {
        // Current position should be at `{`
        if self.tokens.get(self.pos).map(|(t, _, _)| t) != Some(&Token::LBrace) {
            return false;
        }
        // Look at token after `{`
        let after_brace = self.pos + 1;
        match self.tokens.get(after_brace).map(|(t, _, _)| t) {
            // Empty struct literal: `Name { }`
            Some(Token::RBrace) => true,
            // Check for `ident :` pattern (struct field initialization)
            Some(Token::Ident(_)) => {
                matches!(self.tokens.get(after_brace + 1).map(|(t, _, _)| t), Some(Token::Colon))
            }
            _ => false,
        }
    }

    // ─── Program parsing ─────────────────────────────────────────────────────

    pub fn parse_program(&mut self) -> Result<Program> {
        let mut items = Vec::new();
        while !self.at_end() {
            items.push(self.parse_item()?);
        }
        Ok(Program { items })
    }

    fn parse_item(&mut self) -> Result<Item> {
        match self.peek() {
            Some(Token::Const) => self.parse_const_decl().map(Item::ConstDecl),
            Some(Token::DeriveFeltSized) => self.parse_struct_def().map(Item::StructDef),
            Some(Token::ContractAttr) => self.parse_contract_def().map(Item::ContractDef),
            Some(Token::ContractImplAttr) => self.parse_impl_block().map(Item::ImplBlock),
            Some(Token::Mod) => self.parse_mod_decl().map(Item::ModDecl),
            Some(Token::Use) => self.parse_use_decl().map(Item::UseDecl),
            Some(Token::Trait) => self.parse_trait_def(false).map(Item::TraitDef),
            Some(Token::Impl) => {
                // Plain `impl TraitName for StructName { ... }` (without
                // #[contract_implementation])
                self.parse_trait_impl_block().map(Item::TraitImplBlock)
            }
            Some(Token::Pub) => {
                // Could be `pub struct`, `pub mod`, `pub use`, or `pub trait` — peek further
                let saved = self.pos;
                self.advance(); // skip pub
                match self.peek() {
                    Some(Token::Struct) => {
                        self.pos = saved;
                        self.parse_struct_def_no_derive().map(Item::StructDef)
                    }
                    Some(Token::Mod) => {
                        self.pos = saved;
                        self.parse_mod_decl().map(Item::ModDecl)
                    }
                    Some(Token::Use) => {
                        self.pos = saved;
                        self.parse_use_decl().map(Item::UseDecl)
                    }
                    Some(Token::Trait) => {
                        self.pos = saved;
                        self.parse_trait_def(true).map(Item::TraitDef)
                    }
                    _ => {
                        self.pos = saved;
                        bail!("Unexpected `pub` at offset {}", self.peek_span().start)
                    }
                }
            }
            Some(tok) => bail!("Unexpected token {:?} at offset {}", tok, self.peek_span().start),
            None => bail!("Unexpected EOF"),
        }
    }

    // ─── mod / use ─────────────────────────────────────────────────────────

    /// Parse `[pub] mod name;`
    fn parse_mod_decl(&mut self) -> Result<ModDecl> {
        let start = self.peek_span();
        let is_public = self.eat(&Token::Pub);
        self.expect(&Token::Mod)?;
        let (name, _) = self.expect_ident()?;
        let end = self.expect(&Token::Semi)?;
        Ok(ModDecl {
            name,
            is_public,
            span: start.merge(end),
        })
    }

    /// Parse `[pub] use path::to::item;` or `[pub] use path::to::*;`
    fn parse_use_decl(&mut self) -> Result<UseDecl> {
        let start = self.peek_span();
        let _is_public = self.eat(&Token::Pub);
        self.expect(&Token::Use)?;

        let mut path = Vec::new();
        let mut is_glob = false;
        let mut alias = None;

        // Parse first segment
        let (first, _) = self.expect_ident()?;
        path.push(first);

        // Parse remaining segments separated by ::
        while self.eat(&Token::ColonColon) {
            match self.peek() {
                Some(Token::Star) => {
                    self.advance();
                    is_glob = true;
                    break;
                }
                _ => {
                    let (seg, _) = self.expect_ident()?;
                    path.push(seg);
                }
            }
        }

        // Check for alias: `as name`
        if self.eat(&Token::As) {
            let (alias_name, _) = self.expect_ident()?;
            alias = Some(alias_name);
        }

        let end = self.expect(&Token::Semi)?;
        Ok(UseDecl {
            path,
            is_glob,
            alias,
            span: start.merge(end),
        })
    }

    // ─── const ───────────────────────────────────────────────────────────────

    fn parse_const_decl(&mut self) -> Result<ConstDecl> {
        let start = self.peek_span();
        self.expect(&Token::Const)?;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::Colon)?;
        let ty = self.parse_type()?;
        self.expect(&Token::Eq)?;
        let value = self.parse_expr()?;
        let end = self.expect(&Token::Semi)?;
        Ok(ConstDecl {
            name,
            ty,
            value,
            span: start.merge(end),
        })
    }

    // ─── struct ──────────────────────────────────────────────────────────────

    fn parse_struct_def(&mut self) -> Result<StructDef> {
        let start = self.peek_span();
        self.expect(&Token::DeriveFeltSized)?;
        let derives = vec!["FeltSized".to_string()];
        self.eat(&Token::Pub);
        self.expect(&Token::Struct)?;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let fields = self.parse_field_list()?;
        let end = self.expect(&Token::RBrace)?;
        Ok(StructDef {
            name,
            fields,
            derives,
            span: start.merge(end),
        })
    }

    fn parse_struct_def_no_derive(&mut self) -> Result<StructDef> {
        let start = self.peek_span();
        self.eat(&Token::Pub);
        self.expect(&Token::Struct)?;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let fields = self.parse_field_list()?;
        let end = self.expect(&Token::RBrace)?;
        Ok(StructDef {
            name,
            fields,
            derives: vec![],
            span: start.merge(end),
        })
    }

    // ─── contract ────────────────────────────────────────────────────────────

    fn parse_contract_def(&mut self) -> Result<ContractDef> {
        let start = self.peek_span();
        self.expect(&Token::ContractAttr)?;
        self.eat(&Token::Pub);
        self.expect(&Token::Struct)?;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let fields = self.parse_field_list()?;
        let end = self.expect(&Token::RBrace)?;
        Ok(ContractDef {
            name,
            fields,
            span: start.merge(end),
        })
    }

    // ─── impl block ──────────────────────────────────────────────────────────

    fn parse_impl_block(&mut self) -> Result<ImplBlock> {
        let start = self.peek_span();
        self.expect(&Token::ContractImplAttr)?;
        self.expect(&Token::Impl)?;
        let (contract_name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut methods = Vec::new();
        while !self.at(&Token::RBrace) && !self.at_end() {
            methods.push(self.parse_method_def()?);
        }

        let end = self.expect(&Token::RBrace)?;
        Ok(ImplBlock {
            contract_name,
            methods,
            span: start.merge(end),
        })
    }

    // ─── trait ──────────────────────────────────────────────────────────

    /// Parse `[pub] trait Name { fn method_name(&self, ...) -> ReturnType; ...
    /// }`
    fn parse_trait_def(&mut self, _is_pub_prefix: bool) -> Result<TraitDef> {
        let start = self.peek_span();
        let is_public = self.eat(&Token::Pub);
        self.expect(&Token::Trait)?;
        let (name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut methods = Vec::new();
        while !self.at(&Token::RBrace) && !self.at_end() {
            methods.push(self.parse_trait_method_def()?);
        }

        let end = self.expect(&Token::RBrace)?;
        Ok(TraitDef {
            name,
            is_public,
            methods,
            span: start.merge(end),
        })
    }

    /// Parse a method signature (or default implementation) inside a trait
    /// block.
    fn parse_trait_method_def(&mut self) -> Result<TraitMethodDef> {
        let start = self.peek_span();
        self.expect(&Token::Fn)?;
        let (name, _) = self.expect_ident()?;

        // Parameters
        self.expect(&Token::LParen)?;
        let params = self.parse_param_list()?;
        self.expect(&Token::RParen)?;

        // Optional return type
        let return_type = if self.eat(&Token::Arrow) { Some(self.parse_type()?) } else { None };

        // Either `;` (no default) or `{ body }` (default implementation)
        let default_body = if self.at(&Token::LBrace) {
            self.expect(&Token::LBrace)?;
            let body = self.parse_block_body()?;
            self.expect(&Token::RBrace)?;
            Some(body)
        } else {
            self.expect(&Token::Semi)?;
            None
        };

        let end = self.peek_span();
        Ok(TraitMethodDef {
            name,
            params,
            return_type,
            default_body,
            span: start.merge(end),
        })
    }

    /// Parse `impl TraitName for StructName { methods }`
    fn parse_trait_impl_block(&mut self) -> Result<TraitImplBlock> {
        let start = self.peek_span();
        self.expect(&Token::Impl)?;
        let (trait_name, _) = self.expect_ident()?;
        self.expect(&Token::For)?;
        let (target_name, _) = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut methods = Vec::new();
        while !self.at(&Token::RBrace) && !self.at_end() {
            methods.push(self.parse_method_def()?);
        }

        let end = self.expect(&Token::RBrace)?;
        Ok(TraitImplBlock {
            trait_name,
            target_name,
            methods,
            span: start.merge(end),
        })
    }

    fn parse_method_def(&mut self) -> Result<MethodDef> {
        let start = self.peek_span();
        let is_contract_method = self.eat(&Token::ContractMethodAttr);
        let is_pub = self.eat(&Token::Pub);
        self.expect(&Token::Fn)?;
        let (name, _) = self.expect_ident()?;

        // Optional const generics: <const N: usize>
        let generics = if self.eat(&Token::Lt) {
            let mut gs = Vec::new();
            loop {
                if self.at(&Token::Gt) {
                    break;
                }
                self.expect(&Token::Const)?;
                let (gname, gspan) = self.expect_ident()?;
                self.expect(&Token::Colon)?;
                let gty = self.parse_type()?;
                gs.push(ConstGenericParam {
                    name: gname,
                    ty: gty,
                    span: gspan,
                });
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::Gt)?;
            gs
        } else {
            vec![]
        };

        // Parameters
        self.expect(&Token::LParen)?;
        let params = self.parse_param_list()?;
        self.expect(&Token::RParen)?;

        // Optional return type
        let return_type = if self.eat(&Token::Arrow) { Some(self.parse_type()?) } else { None };

        // Body
        self.expect(&Token::LBrace)?;
        let body = self.parse_block_body()?;
        let end = self.expect(&Token::RBrace)?;

        Ok(MethodDef {
            name,
            is_pub,
            is_contract_method,
            generics,
            params,
            return_type,
            body,
            span: start.merge(end),
        })
    }

    // ─── Fields ──────────────────────────────────────────────────────────────

    fn parse_field_list(&mut self) -> Result<Vec<FieldDef>> {
        let mut fields = Vec::new();
        while !self.at(&Token::RBrace) && !self.at_end() {
            let start = self.peek_span();
            let is_pub = self.eat(&Token::Pub);
            let (name, _) = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let ty = self.parse_type()?;

            // Fields end with , or ;
            // Fields end with , or ;
            let _ = self.eat(&Token::Comma) || self.eat(&Token::Semi);
            let end = self.peek_span();

            fields.push(FieldDef {
                name,
                ty,
                is_pub,
                comment: None,
                span: start.merge(end),
            });
        }
        Ok(fields)
    }

    // ─── Parameters ──────────────────────────────────────────────────────────

    fn parse_param_list(&mut self) -> Result<Vec<ParamDef>> {
        let mut params = Vec::new();
        while !self.at(&Token::RParen) && !self.at_end() {
            let start = self.peek_span();

            // Check for &mut self or &self
            if self.at(&Token::Amp) {
                let saved = self.pos;
                self.advance(); // &
                let mutable = self.eat(&Token::Mut);
                if self.peek() == Some(&Token::Ident("self".to_string())) {
                    self.advance();
                    params.push(ParamDef {
                        name: "self".to_string(),
                        ty: ParamType::SelfRef { mutable },
                        span: start.merge(self.peek_span()),
                    });
                    if !self.eat(&Token::Comma) {
                        break;
                    }
                    continue;
                }
                self.pos = saved;
            }

            let (name, _) = self.expect_ident()?;
            self.expect(&Token::Colon)?;

            // Type with possible & or &mut
            let is_ref = self.at(&Token::Amp);
            let mutable = if is_ref {
                self.advance();
                self.eat(&Token::Mut)
            } else {
                false
            };

            let ty = self.parse_type()?;
            params.push(ParamDef {
                name,
                ty: ParamType::Typed { ty, is_ref, mutable },
                span: start.merge(self.peek_span()),
            });

            if !self.eat(&Token::Comma) {
                break;
            }
        }
        Ok(params)
    }

    // ─── Types ───────────────────────────────────────────────────────────────

    fn parse_type(&mut self) -> Result<Type> {
        match self.peek() {
            Some(Token::Felt) => {
                self.advance();
                Ok(Type::Primitive(PrimitiveType::Felt))
            }
            Some(Token::TBool) => {
                self.advance();
                Ok(Type::Primitive(PrimitiveType::Bool))
            }
            Some(Token::TU32) => {
                self.advance();
                Ok(Type::Primitive(PrimitiveType::U32))
            }
            Some(Token::THash) => {
                self.advance();
                Ok(Type::Primitive(PrimitiveType::Hash))
            }
            Some(Token::Usize) => {
                self.advance();
                Ok(Type::Usize)
            }
            Some(Token::LBracket) => {
                // [T; N]
                self.advance();
                let inner = self.parse_type()?;
                self.expect(&Token::Semi)?;
                let len = self.parse_array_len()?;
                self.expect(&Token::RBracket)?;
                Ok(Type::Array(Box::new(inner), len))
            }
            Some(Token::ContractStateArray) => {
                self.advance();
                self.expect(&Token::Lt)?;
                let count = self.parse_array_len()?;
                self.expect(&Token::Comma)?;
                let element_type = self.parse_type()?;
                self.expect(&Token::Gt)?;
                Ok(Type::ContractStateArray {
                    count,
                    element_type: Box::new(element_type),
                })
            }
            Some(Token::ContractHashMap) => {
                self.advance();
                self.expect(&Token::Lt)?;
                let key_type = self.parse_type()?;
                self.expect(&Token::Comma)?;
                let value_type = self.parse_type()?;
                self.expect(&Token::Comma)?;
                let capacity = self.parse_array_len()?;
                self.expect(&Token::Gt)?;
                Ok(Type::ContractHashMap {
                    key_type: Box::new(key_type),
                    value_type: Box::new(value_type),
                    capacity,
                })
            }
            Some(Token::ChainContext) => {
                self.advance();
                Ok(Type::Named("ChainContext".to_string()))
            }
            Some(Token::SelfType) => {
                self.advance();
                Ok(Type::Named("Self".to_string()))
            }
            Some(Token::Amp) => {
                self.advance();
                let mutable = self.eat(&Token::Mut);
                let inner = self.parse_type()?;
                Ok(Type::Ref {
                    inner: Box::new(inner),
                    mutable,
                })
            }
            Some(Token::Ident(_)) => {
                let (name, _) = self.expect_ident()?;
                Ok(Type::Named(name))
            }
            Some(tok) => bail!("Expected type, got {:?} at offset {}", tok, self.peek_span().start),
            None => bail!("Expected type, got EOF"),
        }
    }

    fn parse_array_len(&mut self) -> Result<ArrayLen> {
        match self.peek() {
            Some(Token::IntLiteral(_)) => {
                if let Some((Token::IntLiteral(n), _, _)) = self.advance() {
                    Ok(ArrayLen::Literal(n as usize))
                } else {
                    unreachable!()
                }
            }
            Some(Token::Ident(_)) => {
                let (name, _) = self.expect_ident()?;
                Ok(ArrayLen::Named(name))
            }
            Some(tok) => bail!("Expected array length, got {:?}", tok),
            None => bail!("Expected array length, got EOF"),
        }
    }

    // ─── Statements ──────────────────────────────────────────────────────────

    fn parse_block_body(&mut self) -> Result<Vec<Stmt>> {
        let mut stmts = Vec::new();
        while !self.at(&Token::RBrace) && !self.at_end() {
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt> {
        match self.peek() {
            Some(Token::Let) => self.parse_let_stmt(),
            Some(Token::If) => self.parse_if_stmt(),
            Some(Token::For) => self.parse_for_stmt(),
            Some(Token::While) => self.parse_while_stmt(),
            Some(Token::Return) => self.parse_return_stmt(),
            _ => {
                // Expression or assignment statement
                let expr = self.parse_expr()?;

                // Check for assignment or compound assignment
                if let Some(tok) = self.peek() {
                    if tok == &Token::Eq {
                        let span = expr.span();
                        self.advance();
                        let value = self.parse_expr()?;
                        self.expect(&Token::Semi)?;
                        return Ok(Stmt::Assign { target: expr, value, span });
                    }
                    if let Some(op) = tok.clone().compound_assign_op() {
                        let span = expr.span();
                        self.advance();
                        let value = self.parse_expr()?;
                        self.expect(&Token::Semi)?;
                        return Ok(Stmt::CompoundAssign {
                            target: expr,
                            op,
                            value,
                            span,
                        });
                    }
                }

                self.expect(&Token::Semi)?;
                Ok(Stmt::Expr(expr))
            }
        }
    }

    fn parse_let_stmt(&mut self) -> Result<Stmt> {
        let start = self.peek_span();
        self.expect(&Token::Let)?;
        let (name, _) = self.expect_ident()?;
        let ty = if self.eat(&Token::Colon) { Some(self.parse_type()?) } else { None };
        self.expect(&Token::Eq)?;
        let value = self.parse_expr()?;
        let end = self.expect(&Token::Semi)?;
        Ok(Stmt::Let {
            name,
            ty,
            value,
            span: start.merge(end),
        })
    }

    fn parse_if_stmt(&mut self) -> Result<Stmt> {
        let start = self.peek_span();
        self.expect(&Token::If)?;
        let condition = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let then_block = self.parse_block_body()?;
        self.expect(&Token::RBrace)?;

        let mut else_if_blocks = Vec::new();
        let mut else_block = None;

        while self.eat(&Token::Else) {
            if self.eat(&Token::If) {
                let cond = self.parse_expr()?;
                self.expect(&Token::LBrace)?;
                let body = self.parse_block_body()?;
                self.expect(&Token::RBrace)?;
                else_if_blocks.push((cond, body));
            } else {
                self.expect(&Token::LBrace)?;
                else_block = Some(self.parse_block_body()?);
                self.expect(&Token::RBrace)?;
                break;
            }
        }

        Ok(Stmt::If {
            condition,
            then_block,
            else_if_blocks,
            else_block,
            span: start.merge(self.peek_span()),
        })
    }

    fn parse_for_stmt(&mut self) -> Result<Stmt> {
        let start = self.peek_span();
        self.expect(&Token::For)?;
        let (var, _) = self.expect_ident()?;
        self.expect(&Token::In)?;
        let range_start = self.parse_expr()?;
        self.expect(&Token::DotDot)?;
        let range_end = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let body = self.parse_block_body()?;
        let end = self.expect(&Token::RBrace)?;
        Ok(Stmt::For {
            var,
            start: range_start,
            end: range_end,
            body,
            span: start.merge(end),
        })
    }

    fn parse_while_stmt(&mut self) -> Result<Stmt> {
        let start = self.peek_span();
        self.expect(&Token::While)?;
        let condition = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let body = self.parse_block_body()?;
        let end = self.expect(&Token::RBrace)?;
        Ok(Stmt::While {
            condition,
            body,
            span: start.merge(end),
        })
    }

    fn parse_return_stmt(&mut self) -> Result<Stmt> {
        let start = self.peek_span();
        self.expect(&Token::Return)?;
        let value = if !self.at(&Token::Semi) { Some(self.parse_expr()?) } else { None };
        let end = self.expect(&Token::Semi)?;
        Ok(Stmt::Return {
            value,
            span: start.merge(end),
        })
    }

    // ─── Expressions ─────────────────────────────────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_and_expr()?;
        while self.at(&Token::OrOr) {
            let span = left.span();
            self.advance();
            let right = self.parse_and_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), BinOp::Or, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_comparison_expr()?;
        while self.at(&Token::AndAnd) {
            let span = left.span();
            self.advance();
            let right = self.parse_comparison_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), BinOp::And, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_comparison_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_bitor_expr()?;
        loop {
            let op = match self.peek() {
                Some(Token::EqEq) => BinOp::Eq,
                Some(Token::NotEq) => BinOp::Neq,
                Some(Token::Lt) => BinOp::Lt,
                Some(Token::LtEq) => BinOp::Lte,
                Some(Token::Gt) => BinOp::Gt,
                Some(Token::GtEq) => BinOp::Gte,
                _ => break,
            };
            let span = left.span();
            self.advance();
            let right = self.parse_bitor_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), op, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_bitor_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_bitxor_expr()?;
        while self.at(&Token::Pipe) {
            let span = left.span();
            self.advance();
            let right = self.parse_bitxor_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), BinOp::BitOr, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_bitxor_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_bitand_expr()?;
        while self.at(&Token::Caret) {
            let span = left.span();
            self.advance();
            let right = self.parse_bitand_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), BinOp::BitXor, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_bitand_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_shift_expr()?;
        while self.at(&Token::Amp) {
            let span = left.span();
            self.advance();
            let right = self.parse_shift_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), BinOp::BitAnd, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_shift_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_additive_expr()?;
        loop {
            let op = match self.peek() {
                Some(Token::Shl) => BinOp::Shl,
                Some(Token::Shr) => BinOp::Shr,
                _ => break,
            };
            let span = left.span();
            self.advance();
            let right = self.parse_additive_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), op, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_additive_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_multiplicative_expr()?;
        loop {
            let op = match self.peek() {
                Some(Token::Plus) => BinOp::Add,
                Some(Token::Minus) => BinOp::Sub,
                _ => break,
            };
            let span = left.span();
            self.advance();
            let right = self.parse_multiplicative_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), op, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_multiplicative_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_unary_expr()?;
        loop {
            let op = match self.peek() {
                Some(Token::Star) => BinOp::Mul,
                Some(Token::Slash) => BinOp::Div,
                Some(Token::Percent) => BinOp::Mod,
                _ => break,
            };
            let span = left.span();
            self.advance();
            let right = self.parse_unary_expr()?;
            let end = right.span();
            left = Expr::BinaryOp(Box::new(left), op, Box::new(right), span.merge(end));
        }
        Ok(left)
    }

    fn parse_unary_expr(&mut self) -> Result<Expr> {
        match self.peek() {
            Some(Token::Bang) => {
                let start = self.peek_span();
                self.advance();
                let expr = self.parse_unary_expr()?;
                let end = expr.span();
                Ok(Expr::UnaryOp(UnaryOp::Not, Box::new(expr), start.merge(end)))
            }
            Some(Token::Minus) => {
                let start = self.peek_span();
                self.advance();
                let expr = self.parse_unary_expr()?;
                let end = expr.span();
                Ok(Expr::UnaryOp(UnaryOp::Neg, Box::new(expr), start.merge(end)))
            }
            _ => self.parse_postfix_expr(),
        }
    }

    fn parse_postfix_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_primary_expr()?;

        loop {
            match self.peek() {
                Some(Token::Dot) => {
                    self.advance();
                    let (field_name, field_span) = self.expect_ident()?;

                    // Check for method call: expr.method(args)
                    if self.at(&Token::LParen) {
                        self.advance();
                        let args = self.parse_arg_list()?;
                        self.expect(&Token::RParen)?;
                        let span = expr.span().merge(self.peek_span());
                        expr = Expr::MethodCall {
                            receiver: Box::new(expr),
                            method: field_name,
                            args,
                            span,
                        };
                    }
                    // Check for typed contract access: expr.contract_state::<ABI>(contract_id)
                    else if field_name == "contract_state" && self.at(&Token::ColonColon) {
                        expr = self.parse_typed_contract_access(expr)?;
                    } else {
                        let span = expr.span().merge(field_span);
                        expr = Expr::FieldAccess(Box::new(expr), field_name, span);
                    }
                }
                Some(Token::LBracket) => {
                    let span = expr.span();
                    self.advance();
                    let index = self.parse_expr()?;
                    let end = self.expect(&Token::RBracket)?;
                    expr = Expr::IndexAccess(Box::new(expr), Box::new(index), span.merge(end));
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    fn parse_typed_contract_access(&mut self, user_expr: Expr) -> Result<Expr> {
        let start = user_expr.span();
        // We already consumed `.contract_state`, now expect `::<ABI>`
        self.expect(&Token::ColonColon)?;
        self.expect(&Token::Lt)?;

        // Parse ABI type: `Self::ABI` or `SomeName::ABI`
        let (abi_base, _) = self.expect_ident()?;
        let abi_type = if self.eat(&Token::ColonColon) {
            let (abi_suffix, _) = self.expect_ident()?;
            format!("{}::{}", abi_base, abi_suffix)
        } else {
            abi_base
        };

        self.expect(&Token::Gt)?;
        self.expect(&Token::LParen)?;
        let contract_id = self.parse_expr()?;
        self.expect(&Token::RParen)?;

        // Parse access chain: .field1[index].field2 etc.
        let mut access_chain = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Dot) => {
                    self.advance();
                    let (field, _) = self.expect_ident()?;
                    access_chain.push(AccessStep::Field(field));
                }
                Some(Token::LBracket) => {
                    self.advance();
                    let idx = self.parse_expr()?;
                    self.expect(&Token::RBracket)?;
                    access_chain.push(AccessStep::Index(Box::new(idx)));
                }
                _ => break,
            }
        }

        Ok(Expr::TypedContractAccess {
            user_expr: Box::new(user_expr),
            abi_type,
            contract_id: Box::new(contract_id),
            access_chain,
            span: start.merge(self.peek_span()),
        })
    }

    fn parse_primary_expr(&mut self) -> Result<Expr> {
        match self.peek().cloned() {
            Some(Token::IntLiteral(n)) => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::IntLiteral(n, span))
            }
            Some(Token::True) => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::BoolLiteral(true, span))
            }
            Some(Token::False) => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::BoolLiteral(false, span))
            }
            Some(Token::StringLiteral(s)) => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::StringLiteral(s, span))
            }
            Some(Token::Ident(name)) => {
                let span = self.peek_span();
                self.advance();

                // Check for function call: name(args)
                if self.at(&Token::LParen) {
                    self.advance();
                    let args = self.parse_arg_list()?;
                    let end = self.expect(&Token::RParen)?;
                    Ok(Expr::FunctionCall {
                        name,
                        args,
                        span: span.merge(end),
                    })
                }
                // Check for struct literal: Name { field: value, ... }
                // We need lookahead to distinguish struct literals from blocks:
                // struct literal: `Name { field: value, ... }` — ident followed by `:`
                // not a struct literal: `N { some_statement; }` — e.g. for loop body
                else if self.at(&Token::LBrace) && name.chars().next().map_or(false, |c| c.is_uppercase()) && self.is_struct_literal_ahead() {
                    self.advance();
                    let fields = self.parse_struct_literal_fields()?;
                    let end = self.expect(&Token::RBrace)?;
                    Ok(Expr::StructLiteral {
                        name,
                        fields,
                        span: span.merge(end),
                    })
                }
                // Check for path-qualified function call: module::func(args)
                else if self.at(&Token::ColonColon) {
                    let saved = self.pos;
                    self.advance(); // consume ::
                    if let Some(Token::Ident(_)) = self.peek() {
                        let (func_name, _) = self.expect_ident()?;
                        if self.at(&Token::LParen) {
                            // It's a qualified function call: name::func(args)
                            self.advance(); // consume (
                            let args = self.parse_arg_list()?;
                            let end = self.expect(&Token::RParen)?;
                            let qualified_name = format!("{}::{}", name, func_name);
                            return Ok(Expr::FunctionCall {
                                name: qualified_name,
                                args,
                                span: span.merge(end),
                            });
                        }
                        // Not a function call, backtrack
                        self.pos = saved;
                    } else {
                        self.pos = saved;
                    }
                    Ok(Expr::Ident(name, span))
                } else {
                    Ok(Expr::Ident(name, span))
                }
            }
            Some(Token::SelfType) => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::Ident("Self".to_string(), span))
            }
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }
            Some(Token::LBracket) => {
                let span = self.peek_span();
                self.advance();
                let elements = self.parse_arg_list()?;
                let end = self.expect(&Token::RBracket)?;
                Ok(Expr::ArrayLiteral(elements, span.merge(end)))
            }
            Some(Token::Amp) => {
                // &expr — reference (just parse inner expr, refs are semantic not syntactic)
                let _span = self.peek_span();
                self.advance();
                self.eat(&Token::Mut);
                let inner = self.parse_unary_expr()?;
                // In circuit semantics, & is a no-op. Just return the inner expr.
                Ok(inner)
            }
            Some(tok) => bail!("Unexpected token in expression: {:?} at offset {}", tok, self.peek_span().start),
            None => bail!("Unexpected EOF in expression"),
        }
    }

    fn parse_arg_list(&mut self) -> Result<Vec<Expr>> {
        let mut args = Vec::new();
        if matches!(self.peek(), Some(Token::RParen) | Some(Token::RBracket)) {
            return Ok(args);
        }

        loop {
            args.push(self.parse_expr()?);
            if !self.eat(&Token::Comma) {
                break;
            }
            // Allow trailing comma
            if matches!(self.peek(), Some(Token::RParen) | Some(Token::RBracket)) {
                break;
            }
        }
        Ok(args)
    }

    fn parse_struct_literal_fields(&mut self) -> Result<Vec<(String, Expr)>> {
        let mut fields = Vec::new();
        while !self.at(&Token::RBrace) && !self.at_end() {
            let (name, _) = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let value = self.parse_expr()?;
            fields.push((name, value));
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        Ok(fields)
    }
}
