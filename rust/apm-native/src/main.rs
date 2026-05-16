use clap::{Args, Parser, Subcommand};
use inquire::{Password, Select};
use std::fs;
use std::path::{Path, PathBuf};

mod cloud;
mod crypto;
mod get;
mod lgit;
mod vault;
mod vault_loader;

#[derive(Parser, Debug)]
#[command(name = "pm")]
#[command(about = "APM - Advanced Password Manager", long_about = None)]
struct Cli {
    #[arg(short, long, global = true, value_name = "PATH")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Complete APM setup wizard.
    Setup(SetupArgs),
    /// Add an item. The item parser is ported; storage actions are still Go-only.
    Add(RawArgs),
    /// Get or search vault entries.
    Get(GetArgs),
    /// Generate a password or secret.
    Gen(RawArgs),
    /// Unlock the vault by prompting for the master password.
    Unlock,
    /// Lock session state.
    Lock,
    /// Session commands.
    Session(RawArgs),
    /// Cloud sync operations.
    Cloud {
        #[command(subcommand)]
        command: CloudCommand,
    },
    /// Local Git operations.
    Lgit {
        #[command(subcommand)]
        command: LGitCommand,
    },
    /// Security profile commands.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Authentication and recovery commands.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Policy commands.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Space commands.
    Space {
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// Plugin commands.
    Plugins {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// TOTP commands.
    Totp(RawArgs),
    /// Trust commands.
    Trust(RawArgs),
    /// Import vault data.
    Import(RawArgs),
    /// Export vault data.
    Export(RawArgs),
    /// Vault info.
    Info,
    /// Health check.
    Health,
    /// Mode commands.
    Mode(RawArgs),
    /// Cloud info.
    Cinfo,
    /// Logs.
    Logs(RawArgs),
    /// Compromise mode.
    Compromise(RawArgs),
    /// Vocabulary commands.
    Vocab(RawArgs),
    /// Show loaded extensions.
    Loaded,
    /// FaceID commands.
    Faceid(RawArgs),
    /// Shell injection commands.
    Inject(RawArgs),
    /// Autofill commands.
    Autofill(RawArgs),
    /// Autocomplete commands.
    Autocomplete(RawArgs),
    /// Update this binary.
    Update(RawArgs),
    /// MCP commands.
    Mcp(RawArgs),
    /// Simulated brute-force stress test.
    Brutetest(RawArgs),
    /// Launch the TUI.
    Tui,
}

#[derive(Args, Debug)]
struct SetupArgs {
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Args, Debug)]
struct GetArgs {
    query: Option<String>,
    #[arg(long)]
    show: bool,
}

#[derive(Args, Debug)]
struct RawArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum CloudCommand {
    Init(RawArgs),
    Sync(RawArgs),
    AutoSync(RawArgs),
    Get(RawArgs),
    Diff(RawArgs),
    Delete(RawArgs),
    Reset(RawArgs),
}

#[derive(Subcommand, Debug)]
enum LGitCommand {
    Tree,
    Log(RawArgs),
    Status,
    Show(RawArgs),
    Verify,
    Checkout(RawArgs),
    Squash(RawArgs),
    Undo,
    Prune,
}

#[derive(Subcommand, Debug)]
enum ProfileCommand {
    List,
    Current,
    Status,
    Set { name: String },
    Edit(RawArgs),
    Create(RawArgs),
}

#[derive(Subcommand, Debug)]
enum AuthCommand {
    Email(RawArgs),
    Reset,
    Change,
    Recover,
    Alerts(RawArgs),
    Level(RawArgs),
    Quorum(RawArgs),
    Passkey(RawArgs),
    Codes(RawArgs),
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    Load { name: String },
    Show,
    Clear,
}

#[derive(Subcommand, Debug)]
enum SpaceCommand {
    Switch { name: String },
    List,
    Create { name: String },
}

#[derive(Subcommand, Debug)]
enum PluginCommand {
    Installed,
    List,
    Market(RawArgs),
    Add(RawArgs),
    Install(RawArgs),
    Push(RawArgs),
    Remove(RawArgs),
    Local(RawArgs),
    Search(RawArgs),
    Access(RawArgs),
    Run(RawArgs),
}

fn main() {
    let cli = Cli::parse();
    let vault_path = resolve_vault_path(cli.vault);

    let result = match cli.command {
        Commands::Setup(args) => handle_setup(&vault_path, args.non_interactive),
        Commands::Unlock => handle_unlock(&vault_path).map(|_| ()),
        Commands::Get(args) => handle_get(&vault_path, args),
        Commands::Lgit { command } => handle_lgit(&vault_path, command),
        Commands::Profile { command } => handle_profile(&vault_path, command),
        other => {
            println!("Parsed command: {:?}", other);
            println!("This Rust command body is not ported yet.");
            Ok(())
        }
    };

    if let Err(err) = result {
        eprintln!("\x1b[1;31mError: {}\x1b[0m", err);
        std::process::exit(1);
    }
}

fn resolve_vault_path(cli_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_path {
        return normalize_path(path);
    }
    if let Ok(path) = std::env::var("APM_VAULT_PATH") {
        if !path.trim().is_empty() {
            return normalize_path(PathBuf::from(path));
        }
    }
    normalize_path(PathBuf::from("vault.dat"))
}

fn normalize_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path)
    }
}

fn handle_setup(vault_path: &Path, non_interactive: bool) -> Result<(), String> {
    println!("\x1b[1;36mAPM Setup\x1b[0m");

    if vault_path.exists() {
        println!("Vault already exists: {}", vault_path.display());
        let _ = handle_unlock(vault_path)?;
        return Ok(());
    }

    let master_password = prompt_new_master_password(non_interactive)?;
    let profile_name = if non_interactive {
        "standard".to_string()
    } else {
        Select::new("Choose Security Profile:", vec!["standard", "hardened", "paranoid"])
            .prompt()
            .map_err(|e| e.to_string())?
            .to_string()
    };

    let profile = crypto::get_profile(&profile_name);
    let mut vault = vault::Vault::default();
    vault.profile = Some(profile_name.clone());
    vault.current_profile_params = Some(profile);
    vault.spaces = vec!["default".to_string()];
    vault.current_space = Some("default".to_string());

    let data = crypto::encrypt_vault(&mut vault, &master_password)?;
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(vault_path, data).map_err(|e| e.to_string())?;

    println!("\x1b[1;32mVault created at {}\x1b[0m", vault_path.display());
    println!("Assigned profile: {}", profile_name);
    Ok(())
}

fn prompt_new_master_password(non_interactive: bool) -> Result<String, String> {
    if non_interactive {
        return Err("non-interactive setup needs an existing vault or future password input support".to_string());
    }

    loop {
        let password = Password::new("Create Master Password:")
            .with_help_message("At least 8 characters, with uppercase, lowercase, digit, and symbol.")
            .prompt()
            .map_err(|e| e.to_string())?;
        validate_master_password(&password)?;

        let confirm = Password::new("Confirm Master Password:")
            .prompt()
            .map_err(|e| e.to_string())?;
        if password == confirm {
            return Ok(password);
        }
        println!("\x1b[1;31mPasswords do not match.\x1b[0m");
    }
}

fn prompt_master_password() -> Result<String, String> {
    Password::new("Master Password:")
        .prompt()
        .map_err(|e| e.to_string())
}

fn validate_master_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters long".to_string());
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for ch in password.chars() {
        has_upper |= ch.is_ascii_uppercase();
        has_lower |= ch.is_ascii_lowercase();
        has_digit |= ch.is_ascii_digit();
        has_symbol |= "!@#$%^&*()-_=+".contains(ch);
    }

    if !has_upper {
        return Err("password must contain at least one uppercase letter".to_string());
    }
    if !has_lower {
        return Err("password must contain at least one lowercase letter".to_string());
    }
    if !has_digit {
        return Err("password must contain at least one digit".to_string());
    }
    if !has_symbol {
        return Err("password must contain at least one symbol (!@#$%^&*()-_=+)".to_string());
    }
    Ok(())
}

fn handle_unlock(vault_path: &Path) -> Result<vault::Vault, String> {
    let password = prompt_master_password()?;
    let data = fs::read(vault_path).map_err(|_| format!("Vault not found. Run 'pm setup' or pass --vault. Tried {}", vault_path.display()))?;
    let vault = crypto::decrypt_vault(&data, &password)?;
    println!("\x1b[1;32mVault unlocked.\x1b[0m");
    Ok(vault)
}

fn handle_get(vault_path: &Path, args: GetArgs) -> Result<(), String> {
    let vault = handle_unlock(vault_path)?;
    let query = args.query.unwrap_or_default().to_lowercase();
    let current_space = vault.current_space.as_deref().unwrap_or("default");

    for entry in vault.entries {
        let account_matches = query.is_empty() || entry.account.to_lowercase().contains(&query);
        let space = entry.space.as_deref().unwrap_or("default");
        if account_matches && space == current_space {
            if args.show {
                println!("{} | {} | {}", entry.account, entry.username, entry.password);
            } else {
                println!("{} | {}", entry.account, entry.username);
            }
        }
    }
    Ok(())
}

fn handle_lgit(vault_path: &Path, command: LGitCommand) -> Result<(), String> {
    match command {
        LGitCommand::Status => {
            let (has_history, head, hash, in_sync) = lgit::lgit_status(&vault_path.to_string_lossy())?;
            if !has_history {
                println!("No lgit history.");
            } else {
                println!("HEAD: {}", head);
                println!("Hash: {}", hash);
                println!("Working vault in sync: {}", in_sync);
            }
            Ok(())
        }
        LGitCommand::Verify => {
            let (ok, total) = lgit::verify_lgit_history()?;
            println!("Verified {}/{} commits.", ok, total);
            Ok(())
        }
        LGitCommand::Undo => lgit::undo_lgit(&vault_path.to_string_lossy()),
        LGitCommand::Prune => {
            let (removed, kept) = lgit::prune_lgit_snapshots()?;
            println!("Removed {} stale snapshots, kept {}.", removed, kept);
            Ok(())
        }
        other => {
            println!("Parsed lgit command: {:?}", other);
            println!("This lgit action is not ported yet.");
            Ok(())
        }
    }
}

fn handle_profile(vault_path: &Path, command: ProfileCommand) -> Result<(), String> {
    match command {
        ProfileCommand::List => {
            println!("standard | KDF: argon2id, Time: 3, Memory: 64 MB, Threads: 2, Cipher: aes-gcm");
            println!("hardened | KDF: argon2id, Time: 5, Memory: 256 MB, Threads: 4, Cipher: aes-gcm");
            println!("paranoid | KDF: argon2id, Time: 6, Memory: 512 MB, Threads: 4, Cipher: aes-gcm");
            Ok(())
        }
        ProfileCommand::Current | ProfileCommand::Status => {
            let vault = handle_unlock(vault_path)?;
            let profile = vault.profile.unwrap_or_else(|| "standard".to_string());
            println!("Current profile: {}", profile);
            Ok(())
        }
        ProfileCommand::Set { name } => {
            let _ = crypto::get_profile(&name);
            println!("Parsed profile set: {}", name);
            println!("Profile switching is not ported in Rust yet.");
            Ok(())
        }
        other => {
            println!("Parsed profile command: {:?}", other);
            println!("This profile action is not ported yet.");
            Ok(())
        }
    }
}
