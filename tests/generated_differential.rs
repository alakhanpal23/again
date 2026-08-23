//! Seeded differential corpus for the narrow v0 admission and fingerprint model.
//!
//! This is generated test evidence only. It does not represent external users,
//! production traffic, or commands observed outside this repository.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use again::fingerprint::{FingerprintInput, FingerprintResult, ScopeEntry, fingerprint_scoped};
use again::policy::{AccessPlan, AccessScope, Decision, PolicyContext, classify};
use tempfile::TempDir;

const SEED: u64 = 0xa6a1_2026_5eed_c0de;
const CATEGORY_COUNT: usize = 40;
const ELIGIBLE_CATEGORIES: usize = 16;
const CI_CASES: usize = 10_000;
const FULL_CASES: usize = 100_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Counts {
    eligible: usize,
    noneligible: usize,
}

struct Fixture {
    _temp: TempDir,
    workspace: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary corpus root");
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&outside).expect("outside");
        fs::create_dir(workspace.join("tree")).expect("recursive tree");
        fs::create_dir(workspace.join("listing")).expect("listing directory");
        fs::create_dir(workspace.join(".again")).expect("Again namespace");
        fs::create_dir(workspace.join(".git")).expect("Git namespace");
        fs::create_dir_all(workspace.join(".git/logs")).expect("Git logs");
        fs::write(workspace.join("selected.txt"), b"needle alpha\n").expect("selected file");
        fs::write(workspace.join("other.txt"), b"token beta\n").expect("other file");
        fs::write(workspace.join("unmodeled.txt"), b"unmodeled-00\n").expect("unmodeled file");
        fs::write(workspace.join("tree/nested.txt"), b"needle nested\n").expect("tree file");
        fs::write(workspace.join("listing/member.txt"), b"listing member\n")
            .expect("listing member");
        fs::write(outside.join("secret.txt"), b"outside\n").expect("outside file");
        std::os::unix::fs::symlink(outside.join("secret.txt"), workspace.join("escape"))
            .expect("escaping symlink");

        let executable = temp.path().join("fingerprint-tool");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("fingerprint executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        Self {
            _temp: temp,
            workspace,
            executable,
        }
    }

    fn context(&self, tty: bool) -> PolicyContext<'_> {
        let mut context = PolicyContext::new(&self.workspace, &self.workspace);
        context.stdout_is_tty = tty;
        context
    }
}

#[derive(Clone, Copy)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

struct GeneratedCase {
    command: String,
    eligible: bool,
    tty: bool,
}

fn generate_case(index: usize, random: u64) -> GeneratedCase {
    let count = random % 97 + 1;
    let token = format!("token{:08x}", random as u32);
    let category = index % CATEGORY_COUNT;
    let command = match category {
        0 => "cat selected.txt".to_owned(),
        1 => "cat selected.txt other.txt".to_owned(),
        2 => format!("head -n {count} selected.txt"),
        3 => format!("head --lines={count} selected.txt"),
        4 => format!("tail -c {count} selected.txt"),
        5 => "wc -l selected.txt".to_owned(),
        6 => "wc --words other.txt".to_owned(),
        7 => "ls --color=never listing".to_owned(),
        8 => "ls --color=never -a listing".to_owned(),
        9 => "ls --color=never --sort=name listing".to_owned(),
        10 => "pwd -P".to_owned(),
        11 => "pwd -P".to_owned(),
        12 => format!("grep -n {token} selected.txt"),
        13 => format!("grep -F {token} other.txt"),
        14 => format!("rg --no-ignore --sort=path {token} tree"),
        15 => format!("rg --no-ignore --sort=path -n {token} selected.txt"),
        16 => "cat selected.txt | wc -l".to_owned(),
        17 => format!("cat selected.txt > output-{count}.txt"),
        18 => "cat selected.txt; cat other.txt".to_owned(),
        19 => "cat $HOME/secret".to_owned(),
        20 => "cat $(pwd)/selected.txt".to_owned(),
        21 => "cat *.txt".to_owned(),
        22 => "cat selected.txt\ncat other.txt".to_owned(),
        23 => format!("curl https://example.invalid/{token}"),
        24 => format!("ssh host-{token}"),
        25 => "rm selected.txt".to_owned(),
        26 => format!("touch output-{count}.txt"),
        27 => "cat escape".to_owned(),
        28 => "cat ../outside/secret.txt".to_owned(),
        29 => "cat /etc/passwd".to_owned(),
        30 => "cat .again/cache".to_owned(),
        31 => "cat .git/logs/HEAD".to_owned(),
        32 => "cat -".to_owned(),
        33 => "cat --help selected.txt".to_owned(),
        34 => "ls -l listing".to_owned(),
        35 => format!("rg {token} tree"),
        36 => "again cat selected.txt".to_owned(),
        37 => format!("unknown-command-{token} selected.txt"),
        38 => "'unterminated".to_owned(),
        39 => "pwd".to_owned(),
        _ => unreachable!(),
    };
    GeneratedCase {
        command,
        eligible: category < ELIGIBLE_CATEGORIES,
        tty: category == 39,
    }
}

fn run_generated_corpus(cases: usize) -> Counts {
    assert_eq!(cases % CATEGORY_COUNT, 0, "corpus must contain full blocks");
    let fixture = Fixture::new();
    let mut rng = SplitMix64(SEED);
    let mut counts = Counts::default();

    for index in 0..cases {
        let case = generate_case(index, rng.next());
        let context = fixture.context(case.tty);
        let first = classify(&case.command, context);
        let second = classify(&case.command, context);
        assert_eq!(first, second, "nondeterministic decision for case {index}");

        if case.eligible {
            assert!(
                matches!(first, Decision::ExactReuse { .. }),
                "eligible shape was rejected at case {index}: {:?}",
                case.command
            );
            counts.eligible += 1;
        } else {
            // Hook rewriting requires ExactReuse. Therefore a generated hazard or
            // unsupported shape that reaches either other decision cannot rewrite.
            assert!(
                !matches!(first, Decision::ExactReuse { .. }),
                "non-eligible shape reached rewrite eligibility at case {index}: {:?}",
                case.command
            );
            counts.noneligible += 1;
        }
    }

    let blocks = cases / CATEGORY_COUNT;
    assert_eq!(counts.eligible, blocks * ELIGIBLE_CATEGORIES);
    assert_eq!(
        counts.noneligible,
        blocks * (CATEGORY_COUNT - ELIGIBLE_CATEGORIES)
    );
    verify_scoped_fingerprint_differentials();
    verify_exact_two_run_outputs();
    counts
}

fn scope_entries(plan: &AccessPlan) -> Vec<ScopeEntry> {
    plan.scopes
        .iter()
        .map(|scope| match scope {
            AccessScope::IdentityOnly => ScopeEntry::IdentityOnly,
            AccessScope::ContentPath(path) => ScopeEntry::ContentPath(path.clone()),
            AccessScope::RecursiveContentTree(path) => {
                ScopeEntry::RecursiveContentTree(path.clone())
            }
            AccessScope::DirectoryListing(path) => ScopeEntry::DirectoryListing(path.clone()),
            AccessScope::WholeWorkspace => ScopeEntry::WholeWorkspace,
        })
        .collect()
}

fn scoped_fingerprint(
    fixture: &Fixture,
    argv: &[String],
    plan: &AccessPlan,
    environment: &[(OsString, OsString)],
) -> FingerprintResult {
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    fingerprint_scoped(
        &FingerprintInput {
            argv: &argv,
            cwd: &fixture.workspace,
            workspace: &fixture.workspace,
            environment,
            executable: &fixture.executable,
        },
        &scope_entries(plan),
    )
    .expect("scoped fingerprint")
}

fn exact_decision(fixture: &Fixture, command: &str) -> (Vec<String>, AccessPlan) {
    match classify(command, fixture.context(false)) {
        Decision::ExactReuse { argv, access_plan } => (argv, access_plan),
        decision => panic!("representative was not eligible: {command}: {decision:?}"),
    }
}

fn verify_scoped_fingerprint_differentials() {
    for (index, command) in [
        "pwd -P",
        "cat selected.txt",
        "rg --no-ignore --sort=path needle tree",
        "ls --color=never listing",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let (argv, plan) = exact_decision(&fixture, command);
        let environment = vec![
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ];
        let baseline = scoped_fingerprint(&fixture, &argv, &plan, &environment);
        let repeated = scoped_fingerprint(&fixture, &argv, &plan, &environment);
        assert_eq!(baseline, repeated, "exact fingerprint repeat: {command}");

        fs::write(
            fixture.workspace.join("unmodeled.txt"),
            format!("unmodeled-{index:02}\n"),
        )
        .expect("unmodeled mutation");
        let after_unmodeled = scoped_fingerprint(&fixture, &argv, &plan, &environment);
        assert_eq!(
            baseline.request_digest, after_unmodeled.request_digest,
            "unmodeled input invalidated {command}"
        );

        match command {
            "pwd -P" => {
                let mut changed_environment = environment.clone();
                changed_environment[0].1 = OsString::from("C.UTF-8");
                let changed = scoped_fingerprint(&fixture, &argv, &plan, &changed_environment);
                assert_ne!(baseline.request_digest, changed.request_digest);
                assert_eq!(baseline.workspace_digest, changed.workspace_digest);
            }
            "cat selected.txt" => {
                fs::write(fixture.workspace.join("selected.txt"), b"modeled change\n")
                    .expect("content mutation");
                let changed = scoped_fingerprint(&fixture, &argv, &plan, &environment);
                assert_ne!(baseline.request_digest, changed.request_digest);
            }
            "rg --no-ignore --sort=path needle tree" => {
                fs::write(fixture.workspace.join("tree/added.txt"), b"needle\n")
                    .expect("tree mutation");
                let changed = scoped_fingerprint(&fixture, &argv, &plan, &environment);
                assert_ne!(baseline.request_digest, changed.request_digest);
            }
            "ls --color=never listing" => {
                fs::write(fixture.workspace.join("listing/added.txt"), b"member\n")
                    .expect("listing mutation");
                let changed = scoped_fingerprint(&fixture, &argv, &plan, &environment);
                assert_ne!(baseline.request_digest, changed.request_digest);
            }
            _ => unreachable!(),
        }
    }
}

fn run_twice(executable: &Path, arguments: &[&str], cwd: &Path) -> (Output, Output) {
    let invoke = || {
        Command::new(executable)
            .args(arguments)
            .current_dir(cwd)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("run read-only shadow fixture")
    };
    (invoke(), invoke())
}

fn verify_exact_two_run_outputs() {
    let fixture = Fixture::new();
    let candidates: &[(&str, &[&str])] = &[
        ("/bin/cat", &["selected.txt"]),
        ("/usr/bin/head", &["-n", "1", "selected.txt"]),
        ("/usr/bin/tail", &["-n", "1", "selected.txt"]),
        ("/usr/bin/wc", &["-l", "selected.txt"]),
        ("/bin/ls", &["--color=never", "-a", "listing"]),
        ("/bin/pwd", &["-P"]),
    ];
    let mut executed = 0;
    for (executable, arguments) in candidates {
        let executable = Path::new(executable);
        if !executable.is_file() {
            continue;
        }
        let (first, shadow) = run_twice(executable, arguments, &fixture.workspace);
        assert_eq!(
            first.status, shadow.status,
            "status diverged: {executable:?}"
        );
        assert_eq!(
            first.stdout, shadow.stdout,
            "stdout diverged: {executable:?}"
        );
        assert_eq!(
            first.stderr, shadow.stderr,
            "stderr diverged: {executable:?}"
        );
        executed += 1;
    }
    assert!(executed > 0, "no portable two-run fixture was available");
}

#[test]
fn generated_differential_ci_slice() {
    let counts = run_generated_corpus(CI_CASES);
    assert_eq!(
        counts,
        Counts {
            eligible: 4_000,
            noneligible: 6_000,
        }
    );
}

#[test]
#[ignore = "explicit 100,000-case generated corpus; see docs/CORPUS.md"]
fn generated_differential_100k() {
    let counts = run_generated_corpus(FULL_CASES);
    assert_eq!(
        counts,
        Counts {
            eligible: 40_000,
            noneligible: 60_000,
        }
    );
}
