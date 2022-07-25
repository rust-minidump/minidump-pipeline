use cargo_metadata::{camino::Utf8PathBuf, Message};
use clap::Parser;
use miette::Diagnostic;
use serde::Deserialize;
use std::{fs::File, io::Read, path::PathBuf, process::Command};
use thiserror::Error;

#[derive(Diagnostic, Debug, Error)]
enum PipelineError {
    #[error(transparent)]
    Process(#[from] std::io::Error),
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(action, long)]
    config: Option<PathBuf>,
    #[clap(action, long)]
    run: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfigFile {
    run_dir: String,
    install_dir: String,
    dump_dir: String,
    sym_dir: String,
    report_dir: String,

    #[serde(rename = "minidump-stackwalk")]
    minidump_stackwalk: Dep,
    dump_syms: Dep,
    app: Dep,
}

#[derive(Debug, Clone, Deserialize)]
struct Dep {
    features: Option<Vec<String>>,
    all_features: Option<bool>,
    no_default_features: Option<bool>,

    #[serde(default = "default_true")]
    install: bool,
    #[serde(flatten)]
    kind: DepKind,
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DepKind {
    Git(GitDep),
    Path(PathDep),
    Crates(CratesDep),
}

#[derive(Debug, Clone, Deserialize)]
struct CratesDep {
    version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PathDep {
    path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct GitDep {
    git: String,
    branch: Option<String>,
    tag: Option<String>,
    rev: Option<String>,
}

#[derive(Debug, Clone)]
struct BuildEnv {
    _root_dir: Utf8PathBuf,
    build_dir: Utf8PathBuf,
    install_dir: Utf8PathBuf,
    sym_dir: Utf8PathBuf,
    dump_dir: Utf8PathBuf,
    report_dir: Utf8PathBuf,
    run_dir: Utf8PathBuf,
}

fn main() -> Result<(), miette::Report> {
    let cli = parse_cli();
    let config = parse_config(&cli)?;
    do_pipeline(&cli, &config)?;

    Ok(())
}

fn parse_cli() -> Cli {
    Cli::parse()
}

fn parse_config(cli: &Cli) -> Result<ConfigFile, PipelineError> {
    println!("parsing config...");

    let config_path = cli
        .config
        .to_owned()
        .unwrap_or_else(|| PathBuf::from("pipeline.toml"));
    let file = File::open(config_path)?;
    let mut buf = std::io::BufReader::new(file);
    let mut bytes = Vec::new();
    buf.read_to_end(&mut bytes)?;
    let config = toml::from_slice(&bytes)?;

    println!("config parsed!");
    println!();

    Ok(config)
}

fn do_pipeline(cli: &Cli, config: &ConfigFile) -> Result<(), PipelineError> {
    const APP_NAME: &str = "futility";

    let root_dir = Utf8PathBuf::from_path_buf(std::env::current_dir()?)
        .map_err(|_| PipelineError::Other("current dir isn't utf8?".to_owned()))?;
    let run_name = cli.run.clone().unwrap_or_else(|| "run".to_owned());
    let run_dir = root_dir.join(&config.run_dir).join(run_name);

    let env = BuildEnv {
        install_dir: root_dir.join(&config.install_dir),
        build_dir: root_dir.join(&config.install_dir),
        sym_dir: run_dir.join(&config.sym_dir),
        dump_dir: run_dir.join(&config.dump_dir),
        report_dir: run_dir.join(&config.report_dir),
        run_dir,
        _root_dir: root_dir,
    };

    if env.run_dir.exists() {
        std::fs::remove_dir_all(&env.run_dir)?;
    }

    std::fs::create_dir_all(&env.install_dir)?;
    std::fs::create_dir_all(&env.build_dir)?;
    std::fs::create_dir_all(&env.sym_dir)?;
    std::fs::create_dir_all(&env.dump_dir)?;
    std::fs::create_dir_all(&env.report_dir)?;

    let dump_syms = build("dump_syms", &config.dump_syms, &env)?;
    let mdsw = build("minidump-stackwalk", &config.minidump_stackwalk, &env)?;
    let app = build(APP_NAME, &config.app, &env)?;

    println!();
    println!("artifacts built!");
    println!();

    let _sym = do_dump_syms(&dump_syms, &app, &env)?;
    let minidump = do_run_app(&app, &env)?;
    let _report = do_minidump_stackwalk(&mdsw, &minidump, &env);

    Ok(())
}

fn do_dump_syms(
    dump_syms: &Utf8PathBuf,
    app: &Utf8PathBuf,
    env: &BuildEnv,
) -> Result<Utf8PathBuf, PipelineError> {
    println!("running dump_syms on {app}");

    let output = Command::new(dump_syms).arg(app).output()?;

    let status = output.status;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed dump_syms: {}",
            status.code().unwrap()
        )));
    }

    // MODULE windows x86_64 B71B2A53A4B14BD8B8E60F85DB4AEA1C1 futility.pdb
    // INFO CODE_ID 62DEAF13A3000 futility.exe
    let sym_file = String::from_utf8(output.stdout)?;
    let mut sym_lines = sym_file.lines();
    let module_line = sym_lines.next().unwrap();
    let mut module_items = module_line.split_ascii_whitespace();
    let _module_tok = module_items.next().unwrap();
    let _os = module_items.next().unwrap();
    let _cpu = module_items.next().unwrap();
    let debug_id = module_items.next().unwrap();
    let debug_file = module_items.next().unwrap();

    let output_dir = env.sym_dir.join(debug_file).join(debug_id);
    let mut output_path = output_dir.join(debug_file);
    output_path.set_extension("sym");

    {
        // Write the sym file to its proper location
        use std::io::Write;
        std::fs::create_dir_all(output_dir)?;
        let mut output = std::fs::File::create(&output_path)?;
        write!(&mut output, "{}", sym_file)?;
        output.flush()?;
    }

    println!("dump_syms successful: {output_path}");
    println!();

    Ok(output_path)
}

fn do_run_app(app: &Utf8PathBuf, env: &BuildEnv) -> Result<Utf8PathBuf, PipelineError> {
    println!("running app (TODO)");
    let dump_path = env.dump_dir.join("minidump.dmp");

    let mut task = Command::new(app)
        .arg("--crash-monitor")
        .arg(&dump_path)
        .spawn()?;

    let status = task.wait()?;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed to run app for real: {}",
            status.code().unwrap()
        )));
    }

    println!("failed successfully: {dump_path}");
    println!();

    Ok(dump_path)
}

#[allow(dead_code)]
#[derive(Debug)]
struct MinidumpStackwalkOutput {
    json_report: Utf8PathBuf,
    human_report: Utf8PathBuf,
    logs: Utf8PathBuf,
}

fn do_minidump_stackwalk(
    mdsw: &Utf8PathBuf,
    minidump: &Utf8PathBuf,
    env: &BuildEnv,
) -> Result<MinidumpStackwalkOutput, PipelineError> {
    println!("running minidump-stackwalk");
    let json_report = env.report_dir.join("report.json");
    let human_report = env.report_dir.join("report.human.txt");
    let logs = env.report_dir.join("report.log.txt");

    let mut task = Command::new(mdsw)
        .arg("--cyborg")
        .arg(&json_report)
        .arg("--output-file")
        .arg(&human_report)
        .arg("--log-file")
        .arg(&logs)
        .arg("--verbose=trace")
        .arg("--symbols-path")
        .arg(&env.sym_dir)
        .arg("--pretty")
        .arg(minidump)
        .spawn()?;

    let status = task.wait()?;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed minidump-stackwalk: {}",
            status.code().unwrap()
        )));
    }

    let output = MinidumpStackwalkOutput {
        json_report,
        human_report,
        logs,
    };

    println!("processed report: {output:#?}");
    Ok(output)
}

fn build(to_build: &str, dep: &Dep, env: &BuildEnv) -> Result<Utf8PathBuf, PipelineError> {
    let mut command = Command::new("cargo");
    if dep.install {
        println!("installing {}...", to_build);
        command.arg("install");
        command.arg(to_build);
    } else {
        println!("building {}...", to_build);
        command.arg("build");
        command.current_dir(to_build);
    }

    match &dep.kind {
        DepKind::Crates(dep) => {
            if let Some(version) = &dep.version {
                command.arg("--version").arg(version);
            }
        }
        DepKind::Path(dep) => {
            command.arg("--path").arg(&dep.path);
        }
        DepKind::Git(dep) => {
            command.arg("--git").arg(&dep.git);
            if let Some(branch) = &dep.branch {
                command.arg("--branch").arg(branch);
            }
            if let Some(rev) = &dep.rev {
                command.arg("--rev").arg(rev);
            }
            if let Some(tag) = &dep.tag {
                command.arg("--tag").arg(tag);
            }
        }
    }

    if let Some(features) = &dep.features {
        command.arg("--features");
        for feature in features {
            command.arg(feature);
        }
    }
    if let Some(true) = dep.all_features {
        command.arg("--all-features");
    }
    if let Some(true) = dep.no_default_features {
        command.arg("--no-default-features");
    }

    if dep.install {
        command
            .arg("--root")
            .arg(&env.install_dir)
            .arg("--target-dir")
            .arg(&env.build_dir);
    } else {
        command.arg("--target-dir").arg(&env.build_dir);
    }

    let mut task = command
        .arg("--message-format=json")
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut bin = None;
    let reader = std::io::BufReader::new(task.stdout.take().unwrap());
    for message in cargo_metadata::Message::parse_stream(reader) {
        if let Message::CompilerArtifact(artifact) = message.unwrap() {
            if artifact.target.name == to_build {
                if let Some(executable) = artifact.executable {
                    println!("built {to_build}: {executable}");
                    bin = Some(executable);
                }
            }
        }
    }

    let status = task.wait()?;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed install: {}",
            status.code().unwrap()
        )));
    }

    if dep.install {
        // We need to slurp the binaries out of --list.
        let output = Command::new("cargo")
            .arg("install")
            .arg("--list")
            .arg("--root")
            .arg(&env.install_dir)
            .output()?;

        let messages = String::from_utf8(output.stdout)?;
        let mut lines = messages.lines();

        while let Some(line) = lines.next() {
            if line.starts_with(to_build) {
                if let Some(bin) = lines.next() {
                    let path = env.install_dir.join("bin").join(bin.trim());
                    println!("found already installed {to_build}: {path}");
                    return Ok(path);
                }
            }
        }
    } else if let Some(bin) = bin {
        return Ok(bin);
    }

    Err(PipelineError::Other("failed to find binary!".to_string()))
}
