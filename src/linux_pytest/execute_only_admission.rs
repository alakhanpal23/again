//! Pure lexical scaffold for the first execute-only acceptance fixture.
//!
//! This module deliberately parses only the profile-owned argv after a future
//! CLI has removed `again run --`. A successful parse proves only that those
//! bytes equal the first fixed fixture. It does not inspect the filesystem,
//! create a snapshot, authorize execution, or construct an admitted request.

use super::{LINUX_PYTEST_V1_MAX_SELECTORS, PytestSelectorV1, RefusalCode};

const PYTEST_PREFIX_V1: [&[u8]; 4] = [b".venv/bin/python", b"-I", b"-m", b"pytest"];
const FIRST_EXECUTE_ONLY_SELECTOR_V1: &[u8] = b"tests/test_smoke.py::test_smoke";
const FIRST_EXECUTE_ONLY_ARGC_V1: usize = PYTEST_PREFIX_V1.len() + 1;
const FIRST_EXECUTE_ONLY_SELECTOR_MAX_BYTES_V1: usize = FIRST_EXECUTE_ONLY_SELECTOR_V1.len();

/// Non-authoritative lexical proof for the first execute-only fixture.
///
/// The only owned allocation is the existing Stage-0 selector representation.
/// Its input is length-checked against the fixed fixture before parsing, so an
/// untrusted argv cannot make this scaffold allocate an attacker-sized value.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct FirstExecuteOnlyLexicalAdmissionV1 {
    selector: PytestSelectorV1,
}

impl FirstExecuteOnlyLexicalAdmissionV1 {
    pub(super) fn selector(&self) -> &PytestSelectorV1 {
        &self.selector
    }

    pub(super) fn into_selector(self) -> PytestSelectorV1 {
        self.selector
    }
}

/// Parse the exact inner argv for the first execute-only fixture.
///
/// This function is pure: it neither reads ambient state nor retains borrowed
/// argv storage. Selector parsing reuses the frozen Stage-0 grammar and refusal
/// codes, but a different otherwise-valid selector remains outside this first
/// acceptance slice.
pub(super) fn parse_first_execute_only_argv_v1(
    argv: &[&[u8]],
) -> Result<FirstExecuteOnlyLexicalAdmissionV1, RefusalCode> {
    if argv.len() < PYTEST_PREFIX_V1.len() || argv[..PYTEST_PREFIX_V1.len()] != PYTEST_PREFIX_V1 {
        return Err(RefusalCode::PytestPrefixNotExact);
    }
    if argv.len() == PYTEST_PREFIX_V1.len() {
        return Err(RefusalCode::SelectorMissing);
    }
    let selector_count = argv.len() - PYTEST_PREFIX_V1.len();
    if selector_count > LINUX_PYTEST_V1_MAX_SELECTORS || argv.len() != FIRST_EXECUTE_ONLY_ARGC_V1 {
        return Err(RefusalCode::ForbiddenArgument);
    }

    let raw_selector = argv[PYTEST_PREFIX_V1.len()];
    if raw_selector.len() > FIRST_EXECUTE_ONLY_SELECTOR_MAX_BYTES_V1 {
        return Err(RefusalCode::ForbiddenArgument);
    }
    let selector = PytestSelectorV1::parse(raw_selector)?;
    if selector.raw() != FIRST_EXECUTE_ONLY_SELECTOR_V1 {
        return Err(RefusalCode::ForbiddenArgument);
    }

    Ok(FirstExecuteOnlyLexicalAdmissionV1 { selector })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMOKE_ARGV: [&[u8]; FIRST_EXECUTE_ONLY_ARGC_V1] = [
        b".venv/bin/python",
        b"-I",
        b"-m",
        b"pytest",
        b"tests/test_smoke.py::test_smoke",
    ];

    fn parse_owned(argv: &[Vec<u8>]) -> Result<FirstExecuteOnlyLexicalAdmissionV1, RefusalCode> {
        let borrowed = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
        parse_first_execute_only_argv_v1(&borrowed)
    }

    #[test]
    fn exact_smoke_fixture_has_one_canonical_stage_zero_selector() {
        let parsed = parse_first_execute_only_argv_v1(&SMOKE_ARGV).unwrap();

        assert_eq!(parsed.selector().raw(), FIRST_EXECUTE_ONLY_SELECTOR_V1);
        assert_eq!(parsed.selector().path(), b"tests/test_smoke.py");
        assert_eq!(parsed.selector().nodes(), &[b"test_smoke".to_vec()]);
        assert_eq!(parsed.into_selector().raw(), FIRST_EXECUTE_ONLY_SELECTOR_V1);
    }

    #[test]
    fn prefix_is_byte_exact_at_every_position() {
        for prefix_index in 0..PYTEST_PREFIX_V1.len() {
            for byte_index in 0..PYTEST_PREFIX_V1[prefix_index].len() {
                let mut argv = SMOKE_ARGV
                    .iter()
                    .map(|item| item.to_vec())
                    .collect::<Vec<_>>();
                argv[prefix_index][byte_index] ^= 1;
                assert_eq!(
                    parse_owned(&argv),
                    Err(RefusalCode::PytestPrefixNotExact),
                    "prefix index {prefix_index}, byte index {byte_index}"
                );
            }

            let mut argv = SMOKE_ARGV
                .iter()
                .map(|item| item.to_vec())
                .collect::<Vec<_>>();
            argv[prefix_index] = Vec::new();
            assert_eq!(
                parse_owned(&argv),
                Err(RefusalCode::PytestPrefixNotExact),
                "empty prefix index {prefix_index}"
            );
        }
    }

    #[test]
    fn arity_is_closed_before_selector_allocation() {
        for missing_prefix_count in 0..PYTEST_PREFIX_V1.len() {
            assert_eq!(
                parse_first_execute_only_argv_v1(&SMOKE_ARGV[..missing_prefix_count]),
                Err(RefusalCode::PytestPrefixNotExact)
            );
        }
        assert_eq!(
            parse_first_execute_only_argv_v1(&SMOKE_ARGV[..PYTEST_PREFIX_V1.len()]),
            Err(RefusalCode::SelectorMissing)
        );

        let mut with_extra = SMOKE_ARGV.to_vec();
        with_extra.push(b"tests/test_other.py::test_other");
        assert_eq!(
            parse_first_execute_only_argv_v1(&with_extra),
            Err(RefusalCode::ForbiddenArgument)
        );
    }

    #[test]
    fn selector_reuses_stage_zero_grammar_and_refusal_codes() {
        for (selector, expected) in [
            (b"".as_slice(), RefusalCode::SelectorMalformed),
            (b"-q".as_slice(), RefusalCode::SelectorOptionLike),
            (b"@args.txt".as_slice(), RefusalCode::ForbiddenArgument),
            (
                b"../test_smoke.py::test_smoke".as_slice(),
                RefusalCode::SelectorPathEscape,
            ),
            (
                b"tests/test_smoke.py::".as_slice(),
                RefusalCode::SelectorMalformed,
            ),
            (&[0xff], RefusalCode::SelectorNonUtf8),
        ] {
            let argv = [
                PYTEST_PREFIX_V1[0],
                PYTEST_PREFIX_V1[1],
                PYTEST_PREFIX_V1[2],
                PYTEST_PREFIX_V1[3],
                selector,
            ];
            assert_eq!(parse_first_execute_only_argv_v1(&argv), Err(expected));
        }
    }

    #[test]
    fn other_valid_selectors_and_oversized_inputs_are_closed() {
        let same_length_other = b"tests/test_smoke.py::test_other";
        assert_eq!(
            same_length_other.len(),
            FIRST_EXECUTE_ONLY_SELECTOR_V1.len()
        );
        let other_selector = [
            PYTEST_PREFIX_V1[0],
            PYTEST_PREFIX_V1[1],
            PYTEST_PREFIX_V1[2],
            PYTEST_PREFIX_V1[3],
            same_length_other,
        ];
        assert_eq!(
            parse_first_execute_only_argv_v1(&other_selector),
            Err(RefusalCode::ForbiddenArgument)
        );

        let oversized = vec![b'a'; FIRST_EXECUTE_ONLY_SELECTOR_MAX_BYTES_V1 + 1];
        let oversized_argv = [
            PYTEST_PREFIX_V1[0],
            PYTEST_PREFIX_V1[1],
            PYTEST_PREFIX_V1[2],
            PYTEST_PREFIX_V1[3],
            oversized.as_slice(),
        ];
        assert_eq!(
            parse_first_execute_only_argv_v1(&oversized_argv),
            Err(RefusalCode::ForbiddenArgument)
        );
    }

    #[test]
    fn fixed_adversarial_corpus_is_deterministic() {
        let corpus = [
            SMOKE_ARGV.to_vec(),
            vec![b"again", b"run", b"--", b".venv/bin/python", b"-I"],
            vec![b".venv/bin/python", b"-I", b"-m", b"pytest"],
            vec![
                b"python",
                b"-I",
                b"-m",
                b"pytest",
                FIRST_EXECUTE_ONLY_SELECTOR_V1,
            ],
            vec![
                b".venv/bin/python",
                b"-I",
                b"pytest",
                b"-m",
                FIRST_EXECUTE_ONLY_SELECTOR_V1,
            ],
        ];

        for argv in corpus {
            let first = parse_first_execute_only_argv_v1(&argv);
            let second = parse_first_execute_only_argv_v1(&argv);
            assert_eq!(first, second);
        }
    }
}
