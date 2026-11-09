//! The requirements ledger holds together, and what cites it points at something that is there.
//!
//! The ledger is the module doc of `crates/agent-caps/src/_requirements.rs`. This test reads its
//! tables by header name into a `Ledger` of sum types, then checks five things:
//!
//! 1. shape: the tables have the headers, every cell parses, and no cell holds a square bracket;
//! 2. ids: use cases, principles and requirements are each numbered from 1 without gaps;
//! 3. references inside the ledger resolve, and a use case cites only requirements that are
//!    supported or undecided;
//! 4. every test of the core's behavior cites a use case or a requirement in its doc comment;
//! 5. references from outside the ledger, in the doc comments of the workspace, resolve, and none
//!    of them is a principle.
//!
//! Where a citation points is decided in one place, `Ledger::resolve`; what a ledger row is, in
//! one function per table; which words a cell may hold, in the enums of the ledger module.
//! No network is used: an issue is read as a number and nothing more.

mod support;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use agent_caps::_requirements::{Decision, Layer, Status};
use support::{read, root};

// ---------------------------------------------------------------------------------------------
// Ids

/// A kind of id of the ledger: a prefix and a number.
trait LedgerId: Copy + Eq {
    /// What the id starts with.
    const PREFIX: &'static str;
    fn new(number: u32) -> Self;
    fn number(self) -> u32;
}

macro_rules! ledger_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct $name(u32);

        impl LedgerId for $name {
            const PREFIX: &'static str = $prefix;
            fn new(number: u32) -> Self {
                Self(number)
            }
            fn number(self) -> u32 {
                self.0
            }
        }
    };
}

ledger_id!(UcId, "UC");
ledger_id!(FrId, "FR");
ledger_id!(PId, "P");

/// An id of any kind: what a citation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Id {
    Uc(UcId),
    Fr(FrId),
    P(PId),
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Id::Uc(id) => write!(f, "{}{}", UcId::PREFIX, id.number()),
            Id::Fr(id) => write!(f, "{}{}", FrId::PREFIX, id.number()),
            Id::P(id) => write!(f, "{}{}", PId::PREFIX, id.number()),
        }
    }
}

impl From<UcId> for Id {
    fn from(id: UcId) -> Self {
        Id::Uc(id)
    }
}

impl From<FrId> for Id {
    fn from(id: FrId) -> Self {
        Id::Fr(id)
    }
}

impl From<PId> for Id {
    fn from(id: PId) -> Self {
        Id::P(id)
    }
}

/// The digits of `text` as a number, or `None` when there is anything else or nothing.
fn number(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Too many digits to be a number is still a number that nothing has.
    Some(text.parse().unwrap_or(u32::MAX))
}

/// An id of the kind `T`, such as the prefix FR and a number for `FrId`.
fn parse_id<T: LedgerId>(text: &str) -> Result<T, String> {
    text.strip_prefix(T::PREFIX)
        .and_then(number)
        .map(T::new)
        .ok_or_else(|| format!("`{text}` is not an id of the form {}<number>", T::PREFIX))
}

/// The word of a cell and the successor written after it as `-> <ID>`, the one place that reads
/// that arrow. The id is of the kind the table holds (`T`); another kind is a parse error.
fn parse_successor<T: LedgerId>(cell: &str) -> Result<(&str, Option<T>), String> {
    match cell.split_once("->") {
        None => Ok((cell.trim(), None)),
        Some((word, id)) => Ok((word.trim(), Some(parse_id::<T>(id.trim())?))),
    }
}

/// The ids of the kind `T` that `text` names. A word is an id when it is the prefix of `T` and
/// digits and nothing else, so a trailing comma or a parenthesis around an id still names it,
/// and a letter glued to either end does not.
fn ids_of<T: LedgerId>(text: &str) -> Vec<T> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(|word| parse_id::<T>(word).ok())
        .collect()
}

/// The ids of every kind that `text` names.
fn ids_in(text: &str) -> Vec<Id> {
    let uc = ids_of::<UcId>(text).into_iter().map(Id::Uc);
    let fr = ids_of::<FrId>(text).into_iter().map(Id::Fr);
    let p = ids_of::<PId>(text).into_iter().map(Id::P);
    uc.chain(fr).chain(p).collect()
}

// ---------------------------------------------------------------------------------------------
// The ledger as values

/// A use case of the ledger (its text is checked to be there and not kept).
#[derive(Debug)]
struct UseCase {
    id: UcId,
    state: UcState,
}

#[derive(Debug)]
enum UcState {
    Active { requirements: Vec<FrId> },
    Withdrawn { successor: Option<UcId> },
}

/// A principle of the ledger (its text is checked to be there and not kept).
#[derive(Debug)]
struct Principle {
    id: PId,
    state: PState,
}

#[derive(Debug)]
enum PState {
    Active,
    Withdrawn { successor: Option<PId> },
}

/// A requirement of the ledger.
#[derive(Debug)]
struct Requirement {
    id: FrId,
    text: String,
    state: State,
}

/// What the decision of a requirement allows it to carry. Built from `Decision` by a match
/// without a wildcard, so a new decision does not compile until it is placed here.
#[derive(Debug)]
enum State {
    Supported,
    NotSupported,
    Undecided,
    Withdrawn { successor: Option<FrId> },
}

/// The ledger: every row of its three tables, in order.
#[derive(Debug)]
struct Ledger {
    use_cases: Vec<UseCase>,
    principles: Vec<Principle>,
    requirements: Vec<Requirement>,
}

/// A row that a citation found.
#[derive(Debug)]
enum Found<'a> {
    Uc,
    P,
    Fr(&'a Requirement),
}

/// What a citation names in the ledger.
#[derive(Debug)]
enum Resolved<'a> {
    /// The row exists and holds.
    Found(Found<'a>),
    /// The row exists and was withdrawn, perhaps with a successor.
    Withdrawn { successor: Option<Id> },
    /// There is no such row.
    Missing,
}

impl Ledger {
    /// The one place that tells whether a cited id exists, holds, or was withdrawn.
    fn resolve(&self, id: Id) -> Resolved<'_> {
        match id {
            Id::Uc(id) => match self.use_cases.iter().find(|row| row.id == id) {
                None => Resolved::Missing,
                Some(row) => match &row.state {
                    UcState::Active { .. } => Resolved::Found(Found::Uc),
                    UcState::Withdrawn { successor } => Resolved::Withdrawn {
                        successor: successor.map(Id::Uc),
                    },
                },
            },
            Id::Fr(id) => match self.requirements.iter().find(|row| row.id == id) {
                None => Resolved::Missing,
                Some(row) => match &row.state {
                    State::Withdrawn { successor } => Resolved::Withdrawn {
                        successor: successor.map(Id::Fr),
                    },
                    State::Supported | State::NotSupported | State::Undecided => {
                        Resolved::Found(Found::Fr(row))
                    }
                },
            },
            Id::P(id) => match self.principles.iter().find(|row| row.id == id) {
                None => Resolved::Missing,
                Some(row) => match &row.state {
                    PState::Active => Resolved::Found(Found::P),
                    PState::Withdrawn { successor } => Resolved::Withdrawn {
                        successor: successor.map(Id::P),
                    },
                },
            },
        }
    }
}

/// The message for a citation that does not lead to a row that holds, or `None` when it does.
fn unusable(id: Id, resolved: &Resolved<'_>) -> Option<String> {
    match resolved {
        Resolved::Found(_) => None,
        Resolved::Missing => Some(format!("{id} is not in the ledger")),
        Resolved::Withdrawn { successor: None } => {
            Some(format!("{id} is withdrawn and has no successor"))
        }
        Resolved::Withdrawn {
            successor: Some(next),
        } => Some(format!("{id} is withdrawn; cite {next} instead")),
    }
}

// ---------------------------------------------------------------------------------------------
// Reading the tables

/// A table of the ledger: its header and its rows, each as cells.
struct Table {
    header: Vec<String>,
    rows: Vec<(usize, Vec<String>)>,
}

/// The cells of a line that starts with `|`.
fn cells(line: &str) -> Vec<String> {
    let inner = line.trim().strip_prefix('|').unwrap_or(line);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

/// The tables of `doc`: each run of lines that start with `|`, a header, a rule, then rows.
fn tables(doc: &str) -> Vec<Table> {
    let mut found = Vec::new();
    let mut run: Vec<(usize, &str)> = Vec::new();
    let flush = |run: &mut Vec<(usize, &str)>, found: &mut Vec<Table>| {
        if run.len() >= 2 && is_rule(run[1].1) {
            found.push(Table {
                header: cells(run[0].1),
                rows: run[2..]
                    .iter()
                    .map(|(line, text)| (*line, cells(text)))
                    .collect(),
            });
        }
        run.clear();
    };
    for (n, line) in doc.lines().enumerate() {
        if line.trim_start().starts_with('|') {
            run.push((n + 1, line));
        } else {
            flush(&mut run, &mut found);
        }
    }
    flush(&mut run, &mut found);
    found
}

/// Whether `line` is the rule under a table header, such as `|---|:---:|`. Without it rustdoc
/// renders no table, so a run of `|` lines without it is not read as one either.
fn is_rule(line: &str) -> bool {
    cells(line).iter().all(|cell| {
        let dashes = cell.trim_start_matches(':').trim_end_matches(':');
        !dashes.is_empty() && dashes.bytes().all(|b| b == b'-')
    })
}

/// One row, whose cells are reached by the name of their column.
struct Row<'a> {
    header: &'a [String],
    cells: &'a [String],
}

impl Row<'_> {
    fn get(&self, column: &str) -> &str {
        let at = self
            .header
            .iter()
            .position(|name| name == column)
            .expect("the table was chosen by its header, which has this column");
        &self.cells[at]
    }
}

/// The table whose header is exactly `columns` (in any order), once.
fn table_with<'a>(all: &'a [Table], columns: &[&str]) -> Result<&'a Table, String> {
    let mut want: Vec<&str> = columns.to_vec();
    want.sort_unstable();
    let mut matching = all.iter().filter(|table| {
        let mut have: Vec<&str> = table.header.iter().map(String::as_str).collect();
        have.sort_unstable();
        have == want
    });
    match (matching.next(), matching.next()) {
        (Some(table), None) => Ok(table),
        (None, _) => Err(format!("no table has the header {}", columns.join(" | "))),
        (Some(_), Some(_)) => Err(format!(
            "two tables have the header {}",
            columns.join(" | ")
        )),
    }
}

/// The words of a cell separated by `,`; none for an empty cell.
fn list(cell: &str) -> Vec<&str> {
    cell.split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .collect()
}

fn text_cell(cell: &str) -> Result<String, String> {
    if cell.is_empty() {
        Err("the text is empty".to_owned())
    } else {
        Ok(cell.to_owned())
    }
}

/// Checks that an Issues cell is a list of issue numbers like `#12`; the value is not kept.
fn check_issues_cell(cell: &str) -> Result<(), String> {
    for word in list(cell) {
        if word.strip_prefix('#').and_then(number).is_none() {
            return Err(format!("`{word}` is not an issue number like #12"));
        }
    }
    Ok(())
}

/// Checks that a Layer cell is a list of layers, or `?` alone; the value is not kept.
fn check_layer_cell(cell: &str) -> Result<(), String> {
    let layers = list(cell)
        .into_iter()
        .map(|word| word.parse::<Layer>().map_err(|e| format!("Layer: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    match layers.as_slice() {
        [] => Err("Layer is empty; write ? when it is not decided".to_owned()),
        [_] => Ok(()),
        _ if layers.contains(&Layer::Unknown) => {
            Err("Layer lists ? together with other layers".to_owned())
        }
        _ => Ok(()),
    }
}

/// A status cell: the word as `Status`, and its successor of the kind of the table. Only a
/// withdrawn row has a successor.
fn status_cell<T: LedgerId>(cell: &str) -> Result<(Status, Option<T>), String> {
    let (word, successor) = parse_successor::<T>(cell)?;
    let status = word.parse::<Status>().map_err(|e| format!("Status: {e}"))?;
    match (status, successor) {
        (Status::Active, Some(_)) => Err("an active row has no successor".to_owned()),
        (status, successor) => Ok((status, successor)),
    }
}

fn parse_use_case(row: &Row<'_>) -> Result<UseCase, String> {
    let (status, successor) = status_cell::<UcId>(row.get("Status"))?;
    let requirements = list(row.get("Requirements"))
        .into_iter()
        .map(parse_id::<FrId>)
        .collect::<Result<Vec<_>, _>>()?;
    let state = match status {
        Status::Active if requirements.is_empty() => {
            return Err("an active use case cites at least one requirement".to_owned());
        }
        Status::Active => UcState::Active { requirements },
        Status::Withdrawn => {
            if !requirements.is_empty() {
                return Err("a withdrawn use case cites no requirement".to_owned());
            }
            UcState::Withdrawn { successor }
        }
    };
    text_cell(row.get("Use case"))?;
    Ok(UseCase {
        id: parse_id(row.get("ID"))?,
        state,
    })
}

fn parse_principle(row: &Row<'_>) -> Result<Principle, String> {
    let (status, successor) = status_cell::<PId>(row.get("Status"))?;
    let state = match status {
        Status::Active => PState::Active,
        Status::Withdrawn => PState::Withdrawn { successor },
    };
    text_cell(row.get("Principle"))?;
    Ok(Principle {
        id: parse_id(row.get("ID"))?,
        state,
    })
}

fn parse_requirement(row: &Row<'_>) -> Result<Requirement, String> {
    let (word, successor) = parse_successor::<FrId>(row.get("Decision"))?;
    let decision = word
        .parse::<Decision>()
        .map_err(|e| format!("Decision: {e}"))?;
    if decision != Decision::Withdrawn && successor.is_some() {
        return Err("only a withdrawn row has a successor".to_owned());
    }
    let state = match decision {
        Decision::Supported => State::Supported,
        Decision::Undecided => State::Undecided,
        Decision::NotSupported => State::NotSupported,
        Decision::Withdrawn => State::Withdrawn { successor },
    };
    check_layer_cell(row.get("Layer"))?;
    check_issues_cell(row.get("Issues"))?;
    Ok(Requirement {
        id: parse_id(row.get("ID"))?,
        text: text_cell(row.get("Requirement"))?,
        state,
    })
}

/// Reads the three tables of the ledger doc, the one place that turns a row into a value.
/// Every problem of shape is returned, not only the first. A square bracket in any cell of any
/// table is one of them.
fn parse_ledger(doc: &str) -> Result<Ledger, Vec<String>> {
    let all = tables(doc);
    let mut problems = Vec::new();

    let brackets: Vec<String> = doc
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with('|') && line.contains('['))
        .map(|(n, _)| format!("ledger line {}: a table cell holds a square bracket", n + 1))
        .collect();
    problems.extend(brackets);

    fn rows_of<T>(
        all: &[Table],
        columns: &[&str],
        parse: fn(&Row<'_>) -> Result<T, String>,
        problems: &mut Vec<String>,
    ) -> Vec<T> {
        let table = match table_with(all, columns) {
            Ok(table) => table,
            Err(problem) => {
                problems.push(problem);
                return Vec::new();
            }
        };
        let mut rows = Vec::new();
        for (line, cells) in &table.rows {
            if cells.len() != table.header.len() {
                problems.push(format!(
                    "ledger line {line}: {} cells where the header has {}",
                    cells.len(),
                    table.header.len()
                ));
                continue;
            }
            let row = Row {
                header: &table.header,
                cells,
            };
            match parse(&row) {
                Ok(value) => rows.push(value),
                Err(problem) => problems.push(format!("ledger line {line}: {problem}")),
            }
        }
        rows
    }

    let use_cases = rows_of(
        &all,
        &["ID", "Use case", "Status", "Requirements"],
        parse_use_case,
        &mut problems,
    );
    let principles = rows_of(
        &all,
        &["ID", "Principle", "Status"],
        parse_principle,
        &mut problems,
    );
    let requirements = rows_of(
        &all,
        &["ID", "Requirement", "Decision", "Layer", "Issues"],
        parse_requirement,
        &mut problems,
    );
    if problems.is_empty() {
        Ok(Ledger {
            use_cases,
            principles,
            requirements,
        })
    } else {
        Err(problems)
    }
}

// ---------------------------------------------------------------------------------------------
// Where the ledger and its citations are

/// The ledger file, relative to the workspace root.
const LEDGER_FILE: &str = "crates/agent-caps/src/_requirements.rs";

/// This file, relative to the workspace root. Its docs talk about ids as examples and are left
/// out of the citation scan, as the ledger file is.
const CHECKER_FILE: &str = "crates/agent-caps/tests/requirements.rs";

/// The module doc of the ledger file, without its `//!` markers.
fn ledger_doc(source: &str) -> String {
    source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("//!"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn load() -> Ledger {
    let doc = ledger_doc(&read(&root().join(LEDGER_FILE)));
    parse_ledger(&doc)
        .unwrap_or_else(|problems| panic!("the ledger does not parse:\n{}", problems.join("\n")))
}

/// Every `.rs` file under `dir`, in a stable order.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// The crates of the workspace, in a stable order.
fn crate_dirs(root: &Path) -> Vec<PathBuf> {
    let mut crates: Vec<PathBuf> = fs::read_dir(root.join("crates"))
        .expect("the workspace has a crates directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    crates.sort();
    crates
}

/// An id cited in a doc comment.
struct Citation {
    /// The file, relative to the workspace root.
    file: PathBuf,
    line: usize,
    id: Id,
}

/// The ids cited in the `///` and `//!` lines of `crates/*/src/**` and `crates/*/tests/**`,
/// outside the ledger file, the one place that picks citations up. Principles are picked up too,
/// so that citing one is reported rather than passed over.
fn doc_citations(root: &Path) -> Vec<Citation> {
    let mut files = Vec::new();
    for krate in crate_dirs(root) {
        rust_files(&krate.join("src"), &mut files);
        rust_files(&krate.join("tests"), &mut files);
    }
    let mut found = Vec::new();
    for path in files {
        let file = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if file == Path::new(LEDGER_FILE) || file == Path::new(CHECKER_FILE) {
            continue;
        }
        for (n, line) in read(&path).lines().enumerate() {
            let line_text = line.trim_start();
            if !(line_text.starts_with("///") || line_text.starts_with("//!")) {
                continue;
            }
            for id in ids_in(line_text) {
                found.push(Citation {
                    file: file.clone(),
                    line: n + 1,
                    id,
                });
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------------------------
// The checks, over values

/// Check 2 over one kind: the numbers are 1, 2, 3 and so on.
fn gaps<T: LedgerId>(kind: &str, ids: impl Iterator<Item = T>) -> Vec<String> {
    ids.enumerate()
        .filter(|(at, id)| id.number() as usize != at + 1)
        .map(|(at, id)| {
            format!(
                "{kind} row {} is numbered {}{}",
                at + 1,
                T::PREFIX,
                id.number()
            )
        })
        .collect()
}

/// Check 3: what the ledger cites inside itself.
fn broken_references(ledger: &Ledger) -> Vec<String> {
    let mut problems = Vec::new();
    for case in &ledger.use_cases {
        match &case.state {
            UcState::Active { requirements } => {
                for fr in requirements {
                    let id = Id::Fr(*fr);
                    let resolved = ledger.resolve(id);
                    if let Some(problem) = unusable(id, &resolved) {
                        problems.push(format!("{}: {problem}", Id::Uc(case.id)));
                    } else if let Resolved::Found(Found::Fr(row)) = resolved
                        && matches!(row.state, State::NotSupported)
                    {
                        problems.push(format!(
                            "{} cites {id}, which is not supported",
                            Id::Uc(case.id)
                        ));
                    }
                }
            }
            UcState::Withdrawn { successor } => {
                problems.extend(successor_problems(
                    ledger,
                    Id::Uc(case.id),
                    successor.map(Id::Uc),
                ));
            }
        }
    }
    for principle in &ledger.principles {
        if let PState::Withdrawn { successor } = &principle.state {
            problems.extend(successor_problems(
                ledger,
                Id::P(principle.id),
                successor.map(Id::P),
            ));
        }
    }
    for requirement in &ledger.requirements {
        if let State::Withdrawn { successor } = &requirement.state {
            problems.extend(successor_problems(
                ledger,
                Id::Fr(requirement.id),
                successor.map(Id::Fr),
            ));
        }
        for cited in ids_of::<PId>(&requirement.text).into_iter().map(Id::P) {
            if let Some(problem) = unusable(cited, &ledger.resolve(cited)) {
                problems.push(format!("{}: {problem}", Id::Fr(requirement.id)));
            }
        }
    }
    problems
}

/// The problem with the successor a withdrawn row names, if it has one.
fn successor_problems(ledger: &Ledger, from: Id, successor: Option<Id>) -> Option<String> {
    let next = successor?;
    unusable(next, &ledger.resolve(next)).map(|problem| format!("{from}, successor: {problem}"))
}

/// Check 4: the citations outside the ledger that lead to no row that holds, or that name a
/// principle, which is reached through the requirements and never cited.
fn broken_citations(ledger: &Ledger, citations: &[Citation]) -> Vec<String> {
    citations
        .iter()
        .filter_map(|c| {
            let problem = match c.id {
                Id::P(_) => Some(format!(
                    "{} is a principle; cite the requirement that follows from it",
                    c.id
                )),
                Id::Uc(_) | Id::Fr(_) => unusable(c.id, &ledger.resolve(c.id)),
            };
            problem.map(|problem| format!("{}:{}: {problem}", c.file.display(), c.line))
        })
        .collect()
}

/// Whether the rule that a test cites the ledger applies to a file: the tests of the core's
/// behavior, which are the files under `crates/agent-caps-core/tests/` and the files named
/// `tests.rs` under `crates/*/src/`. The tests of tooling in `crates/agent-caps/tests/` are
/// outside it.
fn tests_must_cite(file: &Path) -> bool {
    let parts: Vec<_> = file.components().map(|c| c.as_os_str()).collect();
    match parts.as_slice() {
        [crates, krate, area, ..] if *crates == "crates" => {
            (*krate == "agent-caps-core" && *area == "tests")
                || (*area == "src" && file.file_name().is_some_and(|n| n == "tests.rs"))
        }
        _ => false,
    }
}

/// The `#[test]` functions of `source` that have no use case or requirement in the `///` lines
/// directly above them (and their attributes), as (line, name).
fn tests_without_citation(source: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let (mut cited, mut is_test) = (false, false);
    for (n, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.starts_with("///") {
            cited |= !ids_of::<UcId>(line).is_empty() || !ids_of::<FrId>(line).is_empty();
        } else if line == "#[test]" {
            is_test = true;
        } else if line.starts_with("#[") {
            // Another attribute between the doc and the function.
        } else {
            if is_test && !cited {
                let name = line.split("fn ").nth(1).and_then(|r| r.split('(').next());
                found.push((n + 1, name.unwrap_or(line).to_owned()));
            }
            (cited, is_test) = (false, false);
        }
    }
    found
}

/// Check 4: every test of the core's behavior cites a use case or a requirement.
fn uncited_tests(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    for krate in crate_dirs(root) {
        rust_files(&krate.join("src"), &mut files);
        rust_files(&krate.join("tests"), &mut files);
    }
    let mut problems = Vec::new();
    for path in files {
        let file = path.strip_prefix(root).unwrap_or(&path);
        if !tests_must_cite(file) {
            continue;
        }
        for (line, name) in tests_without_citation(&read(&path)) {
            problems.push(format!(
                "{}:{line}: test `{name}` cites no UC or FR in its doc comment",
                file.display()
            ));
        }
    }
    problems
}

fn assert_none(what: &str, problems: Vec<String>) {
    assert!(problems.is_empty(), "{what}:\n{}", problems.join("\n"));
}

// ---------------------------------------------------------------------------------------------
// The checks of the workspace

#[test]
fn the_ledger_has_its_tables_and_every_cell_parses() {
    let ledger = load();
    assert!(!ledger.use_cases.is_empty());
    assert!(!ledger.principles.is_empty());
    assert!(!ledger.requirements.is_empty());
}

#[test]
fn ids_are_numbered_from_one_without_gaps() {
    let ledger = load();
    let mut problems = gaps("use case", ledger.use_cases.iter().map(|r| r.id));
    problems.extend(gaps("principle", ledger.principles.iter().map(|r| r.id)));
    problems.extend(gaps(
        "requirement",
        ledger.requirements.iter().map(|r| r.id),
    ));
    assert_none("ids are not 1, 2, 3 and so on", problems);
}

#[test]
fn what_the_ledger_cites_inside_itself_resolves() {
    assert_none(
        "broken references in the ledger",
        broken_references(&load()),
    );
}

#[test]
fn what_the_workspace_cites_in_doc_comments_resolves() {
    let citations = doc_citations(&root());
    assert_none("broken citations", broken_citations(&load(), &citations));
}

#[test]
fn every_test_of_the_core_cites_a_use_case_or_a_requirement() {
    assert_none("tests that cite nothing", uncited_tests(&root()));
}

// ---------------------------------------------------------------------------------------------
// The checks themselves

/// A small ledger: one use case, one principle and two requirements, one of them withdrawn.
const SMALL: &str = "\
| ID | Use case | Status | Requirements |
|---|---|---|---|
| UC1 | Somebody wants something. | active | FR1 |
| UC2 | Somebody wanted something else. | withdrawn -> UC1 | |

| ID | Principle | Status |
|---|---|---|
| P1 | A rule. | active |

| ID | Requirement | Decision | Layer | Issues |
|---|---|---|---|---|
| FR1 | Do it, by P1. | supported | Domain | #3 |
| FR2 | Do it differently. | withdrawn -> FR1 | ? | #4, #5 |
| FR3 | Never do it. | not supported | ? | |
";

fn small() -> Ledger {
    parse_ledger(SMALL).expect("the small ledger parses")
}

#[test]
fn a_successor_is_read_as_the_kind_of_id_the_table_holds() {
    assert_eq!(
        parse_successor::<FrId>("withdrawn -> FR3"),
        Ok(("withdrawn", Some(FrId(3))))
    );
    assert_eq!(
        parse_successor::<FrId>("withdrawn"),
        Ok(("withdrawn", None))
    );
    assert!(parse_successor::<FrId>("withdrawn -> UC3").is_err());
    assert!(parse_successor::<UcId>("withdrawn -> FR3").is_err());
    assert!(parse_successor::<PId>("withdrawn -> P").is_err());
}

#[test]
fn an_id_is_a_whole_word() {
    let found = ids_in("see FR12, (UC3) and P2, not XFR1, FR1b, FR or FR<n>");
    assert_eq!(
        found,
        vec![Id::Uc(UcId(3)), Id::Fr(FrId(12)), Id::P(PId(2))]
    );
    assert_eq!(ids_of::<PId>("by P2 and FR4"), vec![PId(2)]);
}

#[test]
fn a_cited_id_is_found_withdrawn_or_missing() {
    let ledger = small();
    assert!(matches!(
        ledger.resolve(Id::Fr(FrId(1))),
        Resolved::Found(_)
    ));
    assert!(matches!(
        ledger.resolve(Id::Fr(FrId(3))),
        Resolved::Found(_)
    ));
    assert!(matches!(
        ledger.resolve(Id::Fr(FrId(2))),
        Resolved::Withdrawn {
            successor: Some(Id::Fr(FrId(1)))
        }
    ));
    assert!(matches!(ledger.resolve(Id::Uc(UcId(9))), Resolved::Missing));
    let message = unusable(Id::Fr(FrId(2)), &ledger.resolve(Id::Fr(FrId(2)))).unwrap();
    assert_eq!(message, "FR2 is withdrawn; cite FR1 instead");
}

#[test]
fn a_row_that_breaks_the_shape_is_reported() {
    let broken = |from: &str, to: &str| {
        let doc = SMALL.replace(from, to);
        parse_ledger(&doc).expect_err("the shape is broken")
    };
    // A requirement has a layer, or says it does not know.
    assert!(!broken("| supported | Domain |", "| supported | |").is_empty());
    assert!(!broken("| supported | Domain |", "| supported | Domain, ? |").is_empty());
    // Only a withdrawn row has a successor.
    assert!(!broken("| supported |", "| supported -> FR2 |").is_empty());
    // A use case cites a requirement.
    assert!(!broken("| active | FR1 |", "| active | |").is_empty());
    // A word that is not a value of its enum.
    assert!(!broken("| supported |", "| supportive |").is_empty());
    // No square bracket in a cell.
    assert!(!broken("Do it, by P1.", "Do it, see [here].").is_empty());
}

#[test]
fn the_checks_find_what_they_are_for() {
    let ledger = small();
    assert_eq!(
        gaps("requirement", ledger.requirements.iter().map(|r| r.id)).len(),
        0
    );
    assert!(broken_references(&ledger).is_empty());

    // A use case that cites a requirement that is not supported, or withdrawn, or absent.
    let doc = SMALL.replace("| active | FR1 |", "| active | FR3, FR2, FR9 |");
    let problems = broken_references(&parse_ledger(&doc).unwrap());
    assert_eq!(problems.len(), 3, "{problems:?}");

    // A bad issue reference is a parse error, on any decision.
    let doc = SMALL.replace("#4, #5", "#four");
    assert!(parse_ledger(&doc).is_err());

    // A test cites a use case or a requirement in the doc above its attributes.
    let source = "\
/// Checks something, FR7.
#[test]
fn cited() {}

#[test]
fn bare() {}

/// Says nothing of the ledger.
#[test]
fn not_cited() {}

/// UC2
#[test]
#[ignore]
fn cited_above_another_attribute() {}

/// UC2
fn not_a_test() {}
";
    assert_eq!(
        tests_without_citation(source),
        vec![(6, "bare".to_owned()), (10, "not_cited".to_owned())]
    );
    assert!(tests_must_cite(Path::new(
        "crates/agent-caps-core/tests/s/a.rs"
    )));
    assert!(tests_must_cite(Path::new(
        "crates/agent-caps-core/src/domain/tests.rs"
    )));
    assert!(!tests_must_cite(Path::new(
        "crates/agent-caps/tests/agents_map.rs"
    )));
    assert!(!tests_must_cite(Path::new(
        "crates/agent-caps-core/src/domain/event.rs"
    )));

    // A citation outside the ledger of something that is not there.
    let missing = Citation {
        file: PathBuf::from("crates/a/src/lib.rs"),
        line: 7,
        id: Id::Fr(FrId(9)),
    };
    assert_eq!(
        broken_citations(&ledger, &[missing]),
        vec!["crates/a/src/lib.rs:7: FR9 is not in the ledger"]
    );

    // A principle is never cited, even one that is there.
    let principle = Citation {
        file: PathBuf::from("crates/a/tests/t.rs"),
        line: 2,
        id: Id::P(PId(1)),
    };
    assert_eq!(broken_citations(&ledger, &[principle]).len(), 1);

    // Without the rule under its header, rustdoc renders no table, and none is read.
    let doc = SMALL.replace("| Status |\n|---|---|---|\n", "| Status |\n");
    assert_eq!(
        parse_ledger(&doc).unwrap_err(),
        vec!["no table has the header ID | Principle | Status"]
    );
}
