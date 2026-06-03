//! Sigma `condition` expression parser and evaluator.
//!
//! Supported grammar (a pragmatic, security-relevant subset):
//!
//! ```text
//!   expr      := or_expr
//!   or_expr   := and_expr ( 'or'  and_expr )*
//!   and_expr  := not_expr ( 'and' not_expr )*
//!   not_expr  := 'not' not_expr | primary
//!   primary   := '(' expr ')' | quantifier | identifier
//!   quantifier:= ('all' | NUMBER) 'of' ( 'them' | pattern )
//!   pattern   := identifier-with-optional-'*'-wildcard
//! ```
//!
//! Identifiers reference named search-identifiers from the `detection:` block.
//! `*` acts as a wildcard in `N of <pattern>` expansions (`selection*`,
//! `*_filter`). Evaluation is against a map of `search-name → bool`.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionExpr {
    Ident(String),
    Not(Box<ConditionExpr>),
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    /// `all of <pattern>` / `N of <pattern>` (`them` is encoded as pattern `*`).
    Quant { all: bool, n: usize, pattern: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    And,
    Or,
    Not,
    Of,
    All,
    Them,
    Num(usize),
    Ident(String),
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Tok>> {
    let mut toks = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                toks.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                toks.push(Tok::RParen);
            }
            // Identifiers/keywords/numbers: a run of word chars plus '*', '_', '-'.
            c if c.is_alphanumeric() || c == '_' || c == '*' || c == '-' => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' || c == '*' || c == '-' {
                        word.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                toks.push(classify(&word));
            }
            other => bail!("unexpected character in condition: {other:?}"),
        }
    }
    Ok(toks)
}

fn classify(word: &str) -> Tok {
    match word.to_ascii_lowercase().as_str() {
        "and" => Tok::And,
        "or" => Tok::Or,
        "not" => Tok::Not,
        "of" => Tok::Of,
        "all" => Tok::All,
        "them" => Tok::Them,
        _ => {
            if let Ok(n) = word.parse::<usize>() {
                Tok::Num(n)
            } else {
                Tok::Ident(word.to_string())
            }
        }
    }
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn parse_expr(&mut self) -> Result<ConditionExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<ConditionExpr> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let right = self.parse_and()?;
            left = ConditionExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ConditionExpr> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_not()?;
            left = ConditionExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<ConditionExpr> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            let inner = self.parse_not()?;
            Ok(ConditionExpr::Not(Box::new(inner)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<ConditionExpr> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.parse_expr()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => bail!("missing closing parenthesis"),
                }
            }
            Some(Tok::All) => self.parse_quant(true, 0),
            Some(Tok::Num(n)) => self.parse_quant(false, n),
            Some(Tok::Ident(name)) => Ok(ConditionExpr::Ident(name)),
            other => bail!("unexpected token in condition: {other:?}"),
        }
    }

    /// Parse the tail of a quantifier after consuming `all` / `N`.
    fn parse_quant(&mut self, all: bool, n: usize) -> Result<ConditionExpr> {
        match self.next() {
            Some(Tok::Of) => {}
            other => bail!("expected 'of' after quantifier, got {other:?}"),
        }
        let pattern = match self.next() {
            Some(Tok::Them) => "*".to_string(),
            Some(Tok::Ident(p)) => p,
            other => bail!("expected 'them' or a pattern after 'of', got {other:?}"),
        };
        Ok(ConditionExpr::Quant { all, n, pattern })
    }
}

impl ConditionExpr {
    pub fn parse(s: &str) -> Result<Self> {
        let toks = tokenize(s)?;
        if toks.is_empty() {
            bail!("empty condition");
        }
        let mut p = Parser { toks, pos: 0 };
        let e = p.parse_expr()?;
        if p.pos != p.toks.len() {
            return Err(anyhow!("trailing tokens in condition after position {}", p.pos));
        }
        Ok(e)
    }

    /// Evaluate against a map of `search-name → did-it-match`.
    pub fn eval(&self, results: &BTreeMap<String, bool>) -> bool {
        match self {
            ConditionExpr::Ident(name) => *results.get(name).unwrap_or(&false),
            ConditionExpr::Not(inner) => !inner.eval(results),
            ConditionExpr::And(a, b) => a.eval(results) && b.eval(results),
            ConditionExpr::Or(a, b) => a.eval(results) || b.eval(results),
            ConditionExpr::Quant { all, n, pattern } => {
                let matched = results
                    .iter()
                    .filter(|(name, _)| pattern_matches(pattern, name))
                    .filter(|(_, v)| **v)
                    .count();
                let total = results
                    .iter()
                    .filter(|(name, _)| pattern_matches(pattern, name))
                    .count();
                if *all {
                    total > 0 && matched == total
                } else {
                    matched >= (*n).max(1)
                }
            }
        }
    }
}

/// Glob-lite: `*` matches any run. Supports `prefix*`, `*suffix`, `*mid*` and a
/// bare `*` (everything).
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
        (Some(suf), _) if !pattern.ends_with('*') => name.ends_with(suf),
        (_, Some(pre)) if !pattern.starts_with('*') => name.starts_with(pre),
        (Some(_), Some(_)) => {
            let inner = pattern.trim_matches('*');
            name.contains(inner)
        }
        _ => pattern == name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn results(pairs: &[(&str, bool)]) -> BTreeMap<String, bool> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn simple_and_not() {
        let e = ConditionExpr::parse("selection and not filter").unwrap();
        assert!(e.eval(&results(&[("selection", true), ("filter", false)])));
        assert!(!e.eval(&results(&[("selection", true), ("filter", true)])));
        assert!(!e.eval(&results(&[("selection", false), ("filter", false)])));
    }

    #[test]
    fn or_precedence_with_parens() {
        let e = ConditionExpr::parse("(a or b) and c").unwrap();
        assert!(e.eval(&results(&[("a", true), ("b", false), ("c", true)])));
        assert!(!e.eval(&results(&[("a", true), ("b", false), ("c", false)])));
    }

    #[test]
    fn one_of_them_and_all_of_them() {
        let one = ConditionExpr::parse("1 of them").unwrap();
        assert!(one.eval(&results(&[("a", false), ("b", true)])));
        assert!(!one.eval(&results(&[("a", false), ("b", false)])));

        let all = ConditionExpr::parse("all of them").unwrap();
        assert!(all.eval(&results(&[("a", true), ("b", true)])));
        assert!(!all.eval(&results(&[("a", true), ("b", false)])));
    }

    #[test]
    fn quantifier_wildcard_pattern() {
        let e = ConditionExpr::parse("1 of selection*").unwrap();
        assert!(e.eval(&results(&[("selection_a", false), ("selection_b", true), ("filter", false)])));
        assert!(!e.eval(&results(&[("selection_a", false), ("filter", true)])));

        let all = ConditionExpr::parse("all of selection*").unwrap();
        assert!(all.eval(&results(&[("selection_a", true), ("selection_b", true)])));
        assert!(!all.eval(&results(&[("selection_a", true), ("selection_b", false)])));
    }

    #[test]
    fn rejects_garbage() {
        assert!(ConditionExpr::parse("selection and").is_err());
        assert!(ConditionExpr::parse("of them").is_err());
        assert!(ConditionExpr::parse("").is_err());
    }
}
