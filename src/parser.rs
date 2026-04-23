use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use tree_sitter::{Parser, Tree};

pub struct ParsedUnit {
    pub source: Vec<u8>,
    pub tree: Tree,
}

pub fn parse_file(path: &Path) -> Result<ParsedUnit> {
    let source = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_php::language())
        .context("failed to configure PHP parser")?;

    let tree = parser
        .parse(&source, None)
        .context("tree-sitter returned no syntax tree")?;

    Ok(ParsedUnit { source, tree })
}
