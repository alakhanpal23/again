use std::env;
use std::path::Path;
use std::process::Command;

fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    let root = env::var("CARGO_MANIFEST_DIR").expect("Cargo supplies its manifest directory");
    let root = Path::new(&root);
    for path in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = git_output(root, &["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = git_output(root, &["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_output(root, &["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    let sha = git_output(root, &["rev-parse", "HEAD"])
        .filter(|sha| sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let clean =
        git_output(root, &["status", "--porcelain"]).is_some_and(|status| status.is_empty());
    println!(
        "cargo:rustc-env=AGAIN_BUILD_SOURCE_SHA={}",
        sha.unwrap_or_else(|| "unknown".to_owned())
    );
    println!("cargo:rustc-env=AGAIN_BUILD_SOURCE_CLEAN={clean}");
}
