#[path = "../src/agent_gateway_setup.rs"]
mod agent_gateway_setup;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use agent_gateway_setup::{
    AgentGatewayClientV1, AgentGatewaySetupError, AgentGatewaySetupPlanV1, OwnedInstallOutcomeV1,
    install_owned_config,
};
use tempfile::TempDir;

#[test]
fn dry_run_is_deterministic_machine_readable_and_never_writes() {
    let temp = TempDir::new().unwrap();
    let codex_path = temp.path().join("codex-config.toml");
    let claude_path = temp.path().join("claude-config.json");

    let codex = AgentGatewaySetupPlanV1::codex(&codex_path).unwrap();
    let same_codex = AgentGatewaySetupPlanV1::codex(&codex_path).unwrap();
    assert_eq!(codex, same_codex);
    assert_eq!(
        codex.local_cli_command,
        "codex mcp add again -- again mcp serve"
    );
    assert_eq!(codex.stdio.command, "again");
    assert_eq!(codex.stdio.args, ["mcp", "serve"]);
    assert!(!codex.writes_by_default);
    assert!(!codex_path.exists());
    assert!(!codex.ownership_path.exists());
    assert_eq!(
        codex.machine_readable_json().unwrap(),
        same_codex.machine_readable_json().unwrap()
    );
    let value: serde_json::Value =
        serde_json::from_str(&codex.machine_readable_json().unwrap()).unwrap();
    assert_eq!(value["client"], "codex");
    assert_eq!(value["stdio"]["transport"], "stdio");
    assert_eq!(value["writes_by_default"], false);
    assert_eq!(
        codex.to_string(),
        "Dry run only. Install with:\ncodex mcp add again -- again mcp serve"
    );

    let claude = AgentGatewaySetupPlanV1::claude(&claude_path).unwrap();
    assert_eq!(claude.client, AgentGatewayClientV1::Claude);
    assert_eq!(
        claude.local_cli_command,
        "claude mcp add -s user again -- again mcp serve"
    );
    assert!(!claude_path.exists());
    assert!(!claude.ownership_path.exists());
}

#[test]
fn explicit_first_install_creates_exact_private_owned_configs() {
    let temp = TempDir::new().unwrap();
    for (client, name) in [
        (AgentGatewayClientV1::Codex, "config.toml"),
        (AgentGatewayClientV1::Claude, "config.json"),
    ] {
        let directory = temp.path().join(client_name(client));
        fs::create_dir(&directory).unwrap();
        let path = directory.join(name);
        let plan = AgentGatewaySetupPlanV1::dry_run(client, &path).unwrap();
        assert_eq!(
            install_owned_config(&plan).unwrap(),
            OwnedInstallOutcomeV1::Installed
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            plan.managed_config_document()
        );
        assert!(plan.ownership_path.is_file());
        let owner = fs::read_to_string(&plan.ownership_path).unwrap();
        assert!(owner.contains(&plan.ownership_digest));
        assert!(!owner.contains("token"));
        assert!(!owner.contains("secret"));
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&plan.ownership_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn exact_owned_reinstall_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    let plan = AgentGatewaySetupPlanV1::codex(&path).unwrap();
    assert_eq!(
        install_owned_config(&plan).unwrap(),
        OwnedInstallOutcomeV1::Installed
    );
    let before = fs::read(&path).unwrap();
    assert_eq!(
        install_owned_config(&plan).unwrap(),
        OwnedInstallOutcomeV1::AlreadyInstalledOwned
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn existing_unowned_or_conflicting_configuration_is_never_overwritten() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    let user_config = b"[mcp_servers.user]\ncommand = \"user-tool\"\n";
    fs::write(&path, user_config).unwrap();
    let plan = AgentGatewaySetupPlanV1::codex(&path).unwrap();
    assert!(matches!(
        install_owned_config(&plan),
        Err(AgentGatewaySetupError::UnownedConfiguration)
    ));
    assert_eq!(fs::read(&path).unwrap(), user_config);
    assert!(!plan.ownership_path.exists());

    fs::remove_file(&path).unwrap();
    fs::write(&plan.ownership_path, "foreign-owner\n").unwrap();
    assert!(matches!(
        install_owned_config(&plan),
        Err(AgentGatewaySetupError::OwnershipConflict)
    ));
    assert!(!path.exists());
    assert_eq!(
        fs::read_to_string(&plan.ownership_path).unwrap(),
        "foreign-owner\n"
    );
}

#[test]
fn exact_config_without_ownership_is_still_refused() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.json");
    let plan = AgentGatewaySetupPlanV1::claude(&path).unwrap();
    fs::write(&path, plan.managed_config_document()).unwrap();
    assert!(matches!(
        install_owned_config(&plan),
        Err(AgentGatewaySetupError::UnownedConfiguration)
    ));
}

#[test]
fn paths_are_bounded_and_existing_symlinks_are_refused() {
    assert!(matches!(
        AgentGatewaySetupPlanV1::codex(Path::new("relative.toml")),
        Err(AgentGatewaySetupError::InvalidConfigPath)
    ));
    let temp = TempDir::new().unwrap();
    let long_name = format!("{}-config.toml", "x".repeat(300));
    assert!(matches!(
        AgentGatewaySetupPlanV1::codex(temp.path().join(long_name)),
        Err(AgentGatewaySetupError::InvalidConfigPath)
    ));

    #[cfg(unix)]
    {
        let target = temp.path().join("target");
        fs::write(&target, "user data").unwrap();
        let path = temp.path().join("config.toml");
        symlink(&target, &path).unwrap();
        let plan = AgentGatewaySetupPlanV1::codex(&path).unwrap();
        assert!(matches!(
            install_owned_config(&plan),
            Err(AgentGatewaySetupError::UnsafeExistingPath)
        ));
        assert_eq!(fs::read_to_string(&target).unwrap(), "user data");
    }
}

fn client_name(client: AgentGatewayClientV1) -> &'static str {
    match client {
        AgentGatewayClientV1::Codex => "codex",
        AgentGatewayClientV1::Claude => "claude",
    }
}
