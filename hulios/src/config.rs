use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn ensure_default_config_exists() {
    let path = Path::new("/etc/hulios/config.toml");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                if let Err(e) = fs::create_dir_all(parent) {
                    tracing::warn!(
                        "Failed to create configuration directory {:?}: {:?}",
                        parent,
                        e
                    );
                    return;
                }
            }
        }
        if let Err(e) = fs::write(path, hulios_cli::CONFIG_TOML_EXAMPLE) {
            tracing::warn!(
                "Failed to write default configuration template to {:?}: {:?}",
                path,
                e
            );
            return;
        }
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o644);
            if let Err(e) = fs::set_permissions(path, perms) {
                tracing::warn!(
                    "Failed to set permissions on configuration template: {:?}",
                    e
                );
            }
        }
        tracing::info!("Created default configuration template at {:?}", path);
    }
}
