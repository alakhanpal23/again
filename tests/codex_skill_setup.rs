use std::fs;
use std::path::Path;

use again::setup::{
    SetupScope, codex_personal_skill_dir, codex_skill_dir, codex_skill_scope_status,
    install_codex_skill, is_codex_skill_installed, remove_codex_skill,
};
use tempfile::TempDir;

fn project_skill_dir(root: &Path) -> std::path::PathBuf {
    root.join(".agents/skills/again")
}

#[test]
fn documented_personal_and_project_paths_are_used() {
    let temp = TempDir::new().unwrap();
    assert_eq!(
        codex_personal_skill_dir(temp.path()),
        temp.path().join(".agents/skills/again")
    );
    assert_eq!(
        codex_skill_dir(SetupScope::Project, Some(temp.path())).unwrap(),
        temp.path().join(".agents/skills/again")
    );
    assert!(codex_skill_dir(SetupScope::Project, None).is_err());
}

#[test]
fn dry_run_renders_the_skill_without_touching_disk() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    let change = install_codex_skill(&directory, true).unwrap();

    assert!(change.changed);
    assert_eq!(change.path, directory.join("SKILL.md"));
    assert!(change.rendered.starts_with("---\nname: again\n"));
    assert!(change.rendered.contains("call `task.start` once"));
    assert!(change.rendered.contains("`context.delta`"));
    assert!(change.rendered.contains("`context.publish`"));
    assert!(change.rendered.contains("`context.retrieve`"));
    assert!(change.rendered.contains("authenticated local daemon"));
    assert!(
        change
            .rendered
            .contains("Use ordinary shell and editor tools")
    );
    assert!(
        change
            .rendered
            .contains("lookup and proof can cost more than the call itself")
    );
    assert!(change.rendered.contains("again run --"));
    assert!(change.rendered.contains("again reference --"));
    assert!(change.rendered.contains("Never invoke Again's hidden"));
    assert!(!directory.exists());
}

#[test]
fn install_is_idempotent_and_removal_restores_absence() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());

    let first = install_codex_skill(&directory, false).unwrap();
    assert!(first.changed);
    assert!(directory.join("SKILL.md").is_file());
    assert!(directory.join(".again-install-v1.json").is_file());
    assert!(is_codex_skill_installed(&directory).unwrap());

    let second = install_codex_skill(&directory, false).unwrap();
    assert!(!second.changed);
    assert_eq!(fs::read_to_string(&second.path).unwrap(), second.rendered);

    let removed = remove_codex_skill(&directory, false).unwrap();
    assert!(removed.changed);
    assert!(removed.rendered.is_empty());
    assert!(!directory.exists());
    assert!(!is_codex_skill_installed(&directory).unwrap());
}

#[test]
fn unrelated_files_in_an_existing_skill_directory_are_preserved() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    fs::create_dir_all(&directory).unwrap();
    let unrelated = directory.join("team-notes.txt");
    fs::write(&unrelated, "keep me\n").unwrap();

    install_codex_skill(&directory, false).unwrap();
    remove_codex_skill(&directory, false).unwrap();

    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "keep me\n");
    assert!(directory.is_dir());
    assert!(!directory.join("SKILL.md").exists());
    assert!(!directory.join(".again-install-v1.json").exists());
}

#[test]
fn existing_unowned_skill_is_never_overwritten_or_removed() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("SKILL.md");
    let original = "---\nname: again\ndescription: custom\n---\ncustom\n";
    fs::write(&path, original).unwrap();

    let install_error = install_codex_skill(&directory, false).unwrap_err();
    assert!(install_error.to_string().contains("not owned by Again"));
    let remove_error = remove_codex_skill(&directory, false).unwrap_err();
    assert!(remove_error.to_string().contains("not owned by Again"));
    assert_eq!(fs::read_to_string(path).unwrap(), original);
    assert!(!is_codex_skill_installed(&directory).unwrap());
}

#[test]
fn user_edits_after_install_fail_closed() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    install_codex_skill(&directory, false).unwrap();
    let path = directory.join("SKILL.md");
    fs::write(&path, "user replacement\n").unwrap();

    let install_error = install_codex_skill(&directory, false).unwrap_err();
    assert!(install_error.to_string().contains("user-owned changes"));
    let remove_error = remove_codex_skill(&directory, false).unwrap_err();
    assert!(remove_error.to_string().contains("user-owned changes"));
    assert!(is_codex_skill_installed(&directory).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "user replacement\n");
}

#[test]
fn partial_or_malformed_ownership_state_fails_closed() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    install_codex_skill(&directory, false).unwrap();
    fs::remove_file(directory.join("SKILL.md")).unwrap();

    assert!(install_codex_skill(&directory, false).is_err());
    assert!(remove_codex_skill(&directory, false).is_err());
    assert!(is_codex_skill_installed(&directory).is_err());

    fs::write(directory.join("SKILL.md"), "replacement\n").unwrap();
    fs::write(
        directory.join(".again-install-v1.json"),
        r#"{"schema":"wrong","skill_name":"again","installed":"replacement\n"}"#,
    )
    .unwrap();
    assert!(install_codex_skill(&directory, false).is_err());
    assert!(remove_codex_skill(&directory, false).is_err());
}

#[test]
fn removal_dry_run_does_not_change_owned_files() {
    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    install_codex_skill(&directory, false).unwrap();
    let before_skill = fs::read(directory.join("SKILL.md")).unwrap();
    let before_manifest = fs::read(directory.join(".again-install-v1.json")).unwrap();

    let change = remove_codex_skill(&directory, true).unwrap();
    assert!(change.changed);
    assert!(change.rendered.is_empty());
    assert_eq!(fs::read(directory.join("SKILL.md")).unwrap(), before_skill);
    assert_eq!(
        fs::read(directory.join(".again-install-v1.json")).unwrap(),
        before_manifest
    );
}

#[test]
fn duplicate_scope_status_requires_two_distinct_owned_skills() {
    let temp = TempDir::new().unwrap();
    let personal = temp.path().join("personal/again");
    let project = temp.path().join("project/again");
    install_codex_skill(&personal, false).unwrap();
    install_codex_skill(&project, false).unwrap();

    let status = codex_skill_scope_status(&personal, &project).unwrap();
    assert!(status.personal_installed);
    assert!(status.project_installed);
    assert!(status.duplicate_again_skills());

    let same = codex_skill_scope_status(&personal, &personal).unwrap();
    assert!(!same.duplicate_again_skills());
}

#[cfg(unix)]
#[test]
fn symlinked_owned_targets_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let directory = project_skill_dir(temp.path());
    let target = temp.path().join("target");
    fs::create_dir_all(directory.parent().unwrap()).unwrap();
    fs::create_dir_all(&target).unwrap();
    symlink(&target, &directory).unwrap();

    let error = install_codex_skill(&directory, false).unwrap_err();
    assert!(error.to_string().contains("symlink"));
    assert!(fs::read_dir(target).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn symlinked_managed_parent_is_rejected_without_writing_outside_scope() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let target = temp.path().join("outside");
    fs::create_dir_all(&target).unwrap();
    symlink(&target, temp.path().join(".agents")).unwrap();
    let directory = project_skill_dir(temp.path());

    let error = install_codex_skill(&directory, false).unwrap_err();
    assert!(error.to_string().contains("symlink"));
    assert!(fs::read_dir(target).unwrap().next().is_none());
}
