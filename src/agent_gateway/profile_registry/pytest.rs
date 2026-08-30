//! Portable recognition for the frozen pytest profile contract.
//!
//! Recognition is deliberately narrower than pytest's command-line grammar.
//! It classifies one exact selector-shaped invocation as contract-only; it
//! grants neither execution nor reuse authority. Options, plugins, stdin,
//! watch modes, and multiple selectors continue through ordinary uncached
//! execution.

const PYTEST_PREFIX_V1: [&str; 4] = [".venv/bin/python", "-I", "-m", "pytest"];
const MAX_SELECTOR_BYTES_V1: usize = 4_096;

pub(super) fn is_frozen_pytest_contract_v1(argv: &[&str]) -> bool {
    let [python, isolated, module, pytest, selector] = argv else {
        return false;
    };
    python == &PYTEST_PREFIX_V1[0]
        && isolated == &PYTEST_PREFIX_V1[1]
        && module == &PYTEST_PREFIX_V1[2]
        && pytest == &PYTEST_PREFIX_V1[3]
        && valid_selector_v1(selector)
}

fn valid_selector_v1(selector: &str) -> bool {
    if selector.is_empty()
        || selector.len() > MAX_SELECTOR_BYTES_V1
        || selector.starts_with(['-', '/', '\\'])
        || selector.contains(['\0', '\r', '\n', '\\'])
    {
        return false;
    }

    let mut components = selector.split("::");
    let Some(path) = components.next() else {
        return false;
    };
    if !path.ends_with(".py") || !valid_relative_path_v1(path) {
        return false;
    }
    components.all(valid_node_component_v1)
}

fn valid_relative_path_v1(path: &str) -> bool {
    path.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    })
}

fn valid_node_component_v1(component: &str) -> bool {
    !component.is_empty()
        && component.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'[' | b']' | b'-' | b'.')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_one_exact_selector() {
        assert!(is_frozen_pytest_contract_v1(&[
            ".venv/bin/python",
            "-I",
            "-m",
            "pytest",
            "tests/test_unit.py::test_value[param-1]",
        ]));
        for rejected in [
            vec!["python", "-I", "-m", "pytest", "tests/test_unit.py"],
            vec![
                ".venv/bin/python",
                "-I",
                "-m",
                "pytest",
                "tests/test_unit.py",
                "tests/test_other.py",
            ],
            vec![".venv/bin/python", "-I", "-m", "pytest", "--pdb"],
            vec![
                ".venv/bin/python",
                "-I",
                "-m",
                "pytest",
                "../tests/test_unit.py",
            ],
            vec![
                ".venv/bin/python",
                "-I",
                "-m",
                "pytest",
                "tests/test_unit.py::",
            ],
        ] {
            assert!(!is_frozen_pytest_contract_v1(&rejected), "{rejected:?}");
        }
    }
}
