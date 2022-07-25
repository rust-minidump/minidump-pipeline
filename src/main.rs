use cargo_metadata::{camino::Utf8PathBuf, Message};
use clap::Parser;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, process::Command};
use thiserror::Error;

#[derive(Diagnostic, Debug, Error)]
enum PipelineError {
    #[error(transparent)]
    Process(#[from] std::io::Error),
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("some tests failed")]
    TestsFailed,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(action, long)]
    config: Option<PathBuf>,
    #[clap(action, long)]
    run: Option<String>,
    #[clap(action, long)]
    suite: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfigFile {
    #[serde(default = "default_run_dir")]
    run_dir: String,
    #[serde(default = "default_install_dir")]
    install_dir: String,
    #[serde(default = "default_dump_dir")]
    dump_dir: String,
    #[serde(default = "default_sym_dir")]
    sym_dir: String,
    #[serde(default = "default_report_dir")]
    report_dir: String,

    #[serde(rename = "minidump-stackwalk")]
    minidump_stackwalk: Dep,
    dump_syms: Dep,
    #[serde(rename = "minidumper-test")]
    minidumper_test: Dep,
    #[serde(rename = "crash-client")]
    crash_client: Dep,
}

fn default_run_dir() -> String {
    "runs".to_string()
}
fn default_install_dir() -> String {
    "bin".to_string()
}
fn default_dump_dir() -> String {
    "dumps".to_string()
}
fn default_sym_dir() -> String {
    "syms".to_string()
}
fn default_report_dir() -> String {
    "report".to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct Dep {
    #[serde(default)]
    force_build: bool,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    all_features: bool,
    #[serde(default)]
    no_default_features: bool,

    #[serde(flatten)]
    kind: DepKind,
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
    let minidump_stackwalk = build("minidump-stackwalk", &config.minidump_stackwalk, &env)?;
    let app = build("minidumper-test", &config.minidumper_test, &env)?;
    let client = build("crash-client", &&config.crash_client, &env)?;

    println!();
    println!("artifacts built!");
    println!();

    let app_sym = do_dump_syms(
        &dump_syms.installed,
        app.orig_bin_path
            .as_ref()
            .expect("app must be rebuilt for dump_syms!"),
        &env,
    )?;
    let client_sym = do_dump_syms(
        &dump_syms.installed,
        client
            .orig_bin_path
            .as_ref()
            .expect("crash-client must be rebuilt for dump_syms!"),
        &env,
    )?;
    let suite = do_get_suite(&app.installed)?;

    let mut test_results = BTreeMap::new();
    let mut tests_skipped = 0;
    for item in suite {
        if cli.suite.is_empty() || cli.suite.contains(&item) {
            let minidump = do_run_app(&app.installed, &env, &item);
            if let Err(e) = minidump {
                println!("failed to run test! {}", e);
                test_results.insert(
                    item,
                    TestReport {
                        status: TestStatus::FailedRun,
                        dump: None,
                        reports: None,
                    },
                );
                continue;
            }

            let minidump = minidump.unwrap();
            let reports = do_minidump_stackwalk(&minidump_stackwalk.installed, &minidump, &env);
            if let Err(e) = reports {
                println!("failed to process test dump! {}", e);
                test_results.insert(
                    item,
                    TestReport {
                        status: TestStatus::FailedProcess,
                        dump: Some(minidump),
                        reports: None,
                    },
                );
                continue;
            }

            println!("test passed!");
            let reports = reports.unwrap();
            test_results.insert(
                item,
                TestReport {
                    status: TestStatus::Passed,
                    dump: Some(minidump),
                    reports: Some(reports),
                },
            );
        } else {
            tests_skipped += 1;
        }
    }
    println!();
    println!("all tests run!");
    println!();

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut tests_failed = 0;
    for (suite, item) in &test_results {
        tests_run += 1;
        print!("{suite:30} ");
        match item.status {
            TestStatus::Passed => {
                println!("...passed!");
                tests_passed += 1;
            }
            TestStatus::FailedRun => {
                println!("...failed to run!");
                tests_failed += 1;
            }
            TestStatus::FailedProcess => {
                println!("...failed to process dump!");
                tests_failed += 1;
            }
        }
    }

    println!();
    println!(
        "{tests_run} run, {tests_passed} passed, {tests_failed} failed, {tests_skipped} skipped"
    );
    println!();

    let full_report = FullReport {
        stats: TestStats {
            tests_run,
            tests_passed,
            tests_failed,
            tests_skipped,
        },
        builds: BuildReports {
            dump_syms,
            minidump_stackwalk,
            minidumper_test: app,
            crash_client: client,
        },
        syms: SymReports {
            minidumper_test: app_sym,
            crash_client: client_sym,
        },
        tests: test_results,
    };

    let full_report_path = env.run_dir.join("full-report.json");
    let full_report_file = File::create(&full_report_path)?;
    serde_json::to_writer_pretty(full_report_file, &full_report)?;

    println!("full report written to: {}", full_report_path);
    println!();

    if tests_failed > 0 {
        Err(PipelineError::TestsFailed)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FullReport {
    stats: TestStats,
    builds: BuildReports,
    syms: SymReports,
    tests: BTreeMap<String, TestReport>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestStats {
    tests_run: u32,
    tests_passed: u32,
    tests_failed: u32,
    tests_skipped: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SymReports {
    minidumper_test: Utf8PathBuf,
    crash_client: Utf8PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BuildReports {
    dump_syms: InstallOutput,
    minidump_stackwalk: InstallOutput,
    minidumper_test: InstallOutput,
    crash_client: InstallOutput,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestReport {
    status: TestStatus,
    dump: Option<Utf8PathBuf>,
    reports: Option<MinidumpStackwalkOutput>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
enum TestStatus {
    Passed,
    FailedRun,
    FailedProcess,
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

fn do_get_suite(app: &Utf8PathBuf) -> Result<Vec<String>, PipelineError> {
    println!("getting test suite");
    let output = Command::new(app).arg("--list").output()?;

    let status = output.status;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed to get suite listing: {}",
            status.code().unwrap()
        )));
    }

    let stdout = String::from_utf8(output.stdout)?;
    let listing = stdout.lines().map(|s| s.to_owned()).collect();
    println!("got test suite!");
    for item in &listing {
        println!("  {}", item);
    }
    println!();

    Ok(listing)
}

fn do_run_app(
    app: &Utf8PathBuf,
    env: &BuildEnv,
    signal: &str,
) -> Result<Utf8PathBuf, PipelineError> {
    println!("running app --signal={signal}");
    let dump_path = env.dump_dir.join("minidump.dmp");

    let mut task = Command::new(app)
        .arg("--signal")
        .arg(signal)
        .arg("--dump")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn build(to_build: &str, dep: &Dep, env: &BuildEnv) -> Result<InstallOutput, PipelineError> {
    let mut command = Command::new("cargo");
    println!("installing {}...", to_build);

    let is_install = !matches!(dep.kind, DepKind::Path(_));

    if is_install {
        command
            .arg("install")
            .arg(to_build)
            .arg("--root")
            .arg(&env.install_dir)
            .arg("--target-dir")
            .arg(&env.build_dir);
        if dep.force_build {
            command.arg("--force");
        }
    } else {
        command
            .arg("build")
            .arg("--release")
            .arg("--bin")
            .arg(to_build);
    }

    match &dep.kind {
        DepKind::Crates(dep) => {
            if let Some(version) = &dep.version {
                command.arg("--version").arg(version);
            }
        }
        DepKind::Path(dep) => {
            if !is_install {
                command.current_dir(&dep.path);
            } else {
                unreachable!("--install with --path is disabled, it sucks");
            }
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

    if !dep.features.is_empty() {
        command.arg("--features");
        for feature in &dep.features {
            command.arg(feature);
        }
    }
    if dep.all_features {
        command.arg("--all-features");
    }
    if dep.no_default_features {
        command.arg("--no-default-features");
    }

    let mut task = command
        .arg("--message-format=json")
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut orig_bin_path = None;
    let reader = std::io::BufReader::new(task.stdout.take().unwrap());
    for message in cargo_metadata::Message::parse_stream(reader) {
        if let Message::CompilerArtifact(artifact) = message.unwrap() {
            // println!("{}", artifact.target.name);
            if artifact.target.name == to_build {
                // println!("  {:#?}", artifact);
                if let Some(executable) = artifact.executable {
                    println!("built {to_build}: {executable}");
                    orig_bin_path = Some(executable);
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

    if is_install {
        // We need to slurp the binaries out of --list
        // and then copy them back to the build dir
        let output = Command::new("cargo")
            .arg("install")
            .arg("--list")
            .arg("--root")
            .arg(&env.install_dir)
            .output()?;

        let messages = String::from_utf8(output.stdout)?;
        let mut lines = messages.lines().peekable();

        // FORMAT:
        // dump_syms v0.1.0 (C:\Users\ninte\dev\dump_syms):
        //    dump_syms.exe
        // minidump-stackwalk v0.12.0 (C:\Users\ninte\dev\rust-minidump\minidump-stackwalk):
        //    minidump-stackwalk.exe
        // minidumper-test v0.1.0 (C:\Users\ninte\dev\crash-handling\minidumper-test):
        //    crash-client.exe
        //    minidumper-test.exe
        'outer: while let Some(line) = lines.next() {
            if line.starts_with(to_build) {
                while let Some(bin) = lines.peek() {
                    if !bin.starts_with(' ') {
                        continue 'outer;
                    }
                    let bin = lines.next().unwrap();
                    if bin.trim().starts_with(to_build) {
                        let path = env.install_dir.join("bin").join(bin.trim());
                        println!("installed {to_build}: {path}");
                        if let Some(orig_bin_path) = &orig_bin_path {
                            println!("preserving {to_build} at {orig_bin_path}");
                            std::fs::copy(&path, &orig_bin_path)?;
                        }
                        return Ok(InstallOutput {
                            installed: path,
                            orig_bin_path,
                        });
                    }
                }
            }
        }
    } else {
        // Need to copy the binaries to the install dir
        let orig_bin_path = orig_bin_path.expect("built local but didn't get binary path?!");
        let bin_name = orig_bin_path.file_name().unwrap();
        let installed = env.install_dir.join("bin").join(bin_name);
        std::fs::copy(&orig_bin_path, &installed)?;
        return Ok(InstallOutput {
            installed,
            orig_bin_path: Some(orig_bin_path),
        });
    }

    Err(PipelineError::Other("failed to find binary!".to_string()))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct InstallOutput {
    installed: Utf8PathBuf,
    orig_bin_path: Option<Utf8PathBuf>,
}
