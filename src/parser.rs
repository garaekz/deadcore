use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use tree_sitter::{Parser, Tree};

pub struct ParsedUnit {
    pub source: Vec<u8>,
    pub tree: Tree,
}

pub fn line_range_for_span(source: &[u8], start: usize, end: usize) -> (usize, usize) {
    let start = start.min(source.len());
    let end = end.min(source.len());
    (
        line_number_for_offset(source, start),
        line_number_for_offset(source, end),
    )
}

fn line_number_for_offset(source: &[u8], offset: usize) -> usize {
    source[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
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
