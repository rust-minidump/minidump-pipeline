use cargo_metadata::{camino::Utf8PathBuf, Message};
use clap::Parser;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, process::Command};
use thiserror::Error;

////////////////////////////////////////////////////////
/// Configuration
////////////////////////////////////////////////////////

// Feel free to edit this on feature branches to streamline things
const DEFAULT_CONFIG: &str = "pipeline.toml";

/// These are the builtin test-expectations, edit these if there are new rules!
fn get_test_rules(test: &TestKey, cli: &Cli) -> TestRules {
    use TestCheckMode::*;
    use TestRunMode::*;

    // By default, require tests to run completely and pass
    let mut result = TestRules {
        run: Process,
        check: Pass,
    };

    // If the cli has test filters, apply those
    if !cli.suite.is_empty() && !cli.suite.contains(&test.id) {
        result.run = Skip;
        return result;
    }

    // Now apply specific custom expectations for platforms/suites

    // This test doesn't work on these platforms, haven't looked into it
    if cfg!(any(target_os = "windows", target_os = "macos")) && test.signal == "stack-overflow-c-thread" {
        result.check = Busted;
    }
    result
}


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
    #[clap(action, long)]
    debugger: bool,
    #[clap(action, long)]
    inlines: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfigFile {
    /// Whether to pass --inlines to dump_syms (cli flag overrides this)
    inlines: Option<bool>,

    /// What custom `-Csymbol-mangling-version` should be passed to rustc
    #[serde(rename = "rust-mangling")]
    rust_mangling: Option<String>,

    // Various dirs
    #[serde(default = "default_build_dir")]
    build_dir: String,
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

    // Various deps
    #[serde(rename = "minidump-stackwalk")]
    minidump_stackwalk: Dep,
    dump_syms: Dep,
    #[serde(rename = "minidumper-test")]
    minidumper_test: Dep,
    #[serde(rename = "crash-client")]
    crash_client: Dep,
    #[serde(rename = "minidump-debugger")]
    minidump_debugger: Option<Dep>,

    /// Set by code, don't put this in the file
    #[serde(default)]
    name: String,
}

fn default_run_dir() -> String {
    "runs".to_string()
}
fn default_build_dir() -> String {
    "build".to_string()
}
fn default_install_dir() -> String {
    "install".to_string()
}
fn default_dump_dir() -> String {
    "dumps".to_string()
}
fn default_sym_dir() -> String {
    "syms".to_string()
}
fn default_report_dir() -> String {
    "reports".to_string()
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
    /// cargo-install appends /bin to install_dir!
    real_install_dir: Utf8PathBuf,
    sym_dir: Utf8PathBuf,
    dump_dir: Utf8PathBuf,
    report_dir: Utf8PathBuf,
    run_dir: Utf8PathBuf,
    rust_mangling: Option<String>,
}

/////////////////////////////////////////////////////////
/// Testing and Reporting
/////////////////////////////////////////////////////////

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
    rules: TestRules,
    status: TestStatus,
    dump: Option<Utf8PathBuf>,
    reports: Option<MinidumpStackwalkOutput>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
enum TestStatus {
    Skipped,
    Passed,
    FailedRun,
    FailedProcess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestKey {
    signal: String,
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestRules {
    run: TestRunMode,
    check: TestCheckMode,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
enum TestRunMode {
    Skip,
    // Build,
    Run,
    Process,
    // Check,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
enum TestCheckMode {
    Pass,
    Fail,
    Busted,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinidumpStackwalkOutput {
    json_report: Utf8PathBuf,
    human_report: Utf8PathBuf,
    logs: Utf8PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct InstallOutput {
    installed: Utf8PathBuf,
    orig_bin_path: Option<Utf8PathBuf>,
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
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let file = File::open(&config_path)?;
    let mut buf = std::io::BufReader::new(file);
    let mut bytes = Vec::new();
    buf.read_to_end(&mut bytes)?;
    let mut config: ConfigFile = toml::from_slice(&bytes)?;
    config.name = config_path
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    println!("config parsed!");
    println!();

    Ok(config)
}

/// Run through the full pipeline:
/// 
/// * Stage 1: build
/// * Stage 2: dump_syms
/// * Stage 3: run + crash
/// * Stage 4: minidump-stackalk
/// * Stage 5: view
fn do_pipeline(cli: &Cli, config: &ConfigFile) -> Result<(), PipelineError> {
    // Stage 0: Figure out where we're going to put stuff, and clean up
    let root_dir = Utf8PathBuf::from_path_buf(std::env::current_dir()?)
        .map_err(|_| PipelineError::Other("current dir isn't utf8?".to_owned()))?;
    let run_name = cli.run.clone().unwrap_or_else(|| config.name.clone());
    let run_dir = root_dir.join(&config.run_dir).join(run_name);

    let env = BuildEnv {
        install_dir: run_dir.join(&config.install_dir),
        real_install_dir: run_dir.join(&config.install_dir).join("bin"),
        build_dir: run_dir.join(&config.build_dir),
        sym_dir: run_dir.join(&config.sym_dir),
        dump_dir: run_dir.join(&config.dump_dir),
        report_dir: run_dir.join(&config.report_dir),
        run_dir,
        _root_dir: root_dir,
        rust_mangling: config.rust_mangling.clone(),
    };

    prep_run_dir(&env)?;

    // Stage 1: Build/install everything we need
    let dump_syms = build("dump_syms", &config.dump_syms, &env)?;
    let minidump_stackwalk = build("minidump-stackwalk", &config.minidump_stackwalk, &env)?;
    let app = build("minidumper-test", &config.minidumper_test, &env)?;
    let client = build("crash-client", &config.crash_client, &env)?;
    let debugger = if cli.debugger {
        let dep = config
            .minidump_debugger
            .as_ref()
            .expect("your config doesn't have [minidump-debugger]!");
        Some(build("minidump-debugger", dep, &env)?)
    } else {
        None
    };
    println!();
    println!("artifacts built!");
    println!();

    // Stage 2: Get symbols for the crashing binary with dump_syms
    let default_inlines = false;
    let inlines = config.inlines.unwrap_or(default_inlines) || cli.inlines;
    let client_path = client
        .orig_bin_path
        .as_ref()
        .expect("crash-client must be rebuilt for dump_syms!");
    let client_sym = do_dump_syms(&dump_syms.installed, client_path, &env, inlines)?;

    // Stage 3 + Stage 4: Run the suite and get a report
    let suite = do_get_suite(&app.installed)?;
    let full_report = do_run_tests(
        suite,
        &cli,
        &env,
        dump_syms,
        app,
        client,
        minidump_stackwalk,
        client_sym,
    )?;

    // Stage 5: Optionally launch the debugger
    if let Some(debugger) = &debugger {
        do_run_debugger(&debugger.installed, &full_report, &env)?;
    }

    // Set non-zero status if need be
    if full_report.stats.tests_failed > 0 {
        Err(PipelineError::TestsFailed)
    } else {
        Ok(())
    }
}

/// Stage 0: Delete everything but build/install in the runs/$RUN dir, then recreate the dirs we'll use.
fn prep_run_dir(env: &BuildEnv) -> Result<(), PipelineError> {
    if env.run_dir.exists() {
        let build_dir_name = env.build_dir.file_name().unwrap();
        let install_dir_name = env.install_dir.file_name().unwrap();

        for item in std::fs::read_dir(&env.run_dir)? {
            let item = item?;
            let raw_item_name = item.file_name();
            let item_name = raw_item_name.to_string_lossy();
            if item_name != build_dir_name && item_name != install_dir_name {
                let item_type = item.file_type()?;
                if item_type.is_dir() {
                    std::fs::remove_dir_all(&item.path())?;
                } else if item_type.is_file() {
                    std::fs::remove_file(&item.path())?;
                }
            }
        }
    }

    std::fs::create_dir_all(&env.install_dir)?;
    std::fs::create_dir_all(&env.real_install_dir)?;
    std::fs::create_dir_all(&env.build_dir)?;
    std::fs::create_dir_all(&env.run_dir)?;
    std::fs::create_dir_all(&env.sym_dir)?;
    std::fs::create_dir_all(&env.dump_dir)?;
    std::fs::create_dir_all(&env.report_dir)?;

    Ok(())
}

/// Stage 3+4: Run the crashing app and then run minidump-stackwalk on it
fn do_run_tests(
    suite: Vec<TestKey>,
    cli: &Cli,
    env: &BuildEnv,
    dump_syms: InstallOutput,
    app: InstallOutput,
    client: InstallOutput,
    minidump_stackwalk: InstallOutput,
    client_sym: Utf8PathBuf,
) -> Result<FullReport, PipelineError> {
    let mut test_results = BTreeMap::new();
    for test in suite {
        let rules = get_test_rules(&test, cli);
        let mut report = test_results.entry(test.id.clone()).or_insert(TestReport {
            rules,
            status: TestStatus::Passed,
            dump: None,
            reports: None,
        });
        if report.rules.run <= TestRunMode::Skip {
            report.status = TestStatus::Skipped;
            continue;
        }

        // Ok run the test
        let minidump = do_run_app(&app.installed, &env, &test);
        if let Err(e) = minidump {
            println!("failed to run test! {}", e);
            report.status = TestStatus::FailedRun;
            continue;
        }
        report.dump = minidump.ok();
        let minidump = report.dump.as_ref().unwrap();

        if report.rules.run <= TestRunMode::Run {
            continue;
        }

        let reports = do_minidump_stackwalk(&minidump_stackwalk.installed, minidump, &env, &test);
        if let Err(e) = reports {
            println!("failed to process test dump! {}", e);
            report.status = TestStatus::FailedProcess;
            continue;
        }

        println!("test passed!");
        report.reports = reports.ok();
    }
    println!();
    println!("all tests run!");
    println!();

    let mut tests_skipped = 0;
    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut tests_failed = 0;
    for (suite, item) in &test_results {
        tests_run += 1;
        print!("{suite:30} ");
        match (&item.status, &item.rules.check) {
            (TestStatus::Skipped, _) => {
                println!("...skipped!");
                tests_skipped += 1;
            }
            (_, TestCheckMode::Random)
            | (TestStatus::Passed, TestCheckMode::Pass)
            | (TestStatus::FailedRun | TestStatus::FailedProcess, TestCheckMode::Fail) => {
                println!("...passed!");
                tests_passed += 1;
            }
            (TestStatus::FailedRun, TestCheckMode::Busted) => {
                println!("...failed to run! (known busted, treated as pass)");
                tests_passed += 1;
            }
            (TestStatus::FailedProcess, TestCheckMode::Busted) => {
                println!("...failed to process dump! (known busted, treated as pass)");
                tests_passed += 1;
            }
            (TestStatus::FailedRun, TestCheckMode::Pass) => {
                println!("...failed to run!");
                tests_failed += 1;
            }
            (TestStatus::FailedProcess, TestCheckMode::Pass) => {
                println!("...failed to process dump!");
                tests_failed += 1;
            }
            (TestStatus::Passed, TestCheckMode::Busted) => {
                println!("...got fixed (change the expected to 'pass')!");
                tests_failed += 1;
            }
            (TestStatus::Passed, TestCheckMode::Fail) => {
                println!("...incorrectly passed!");
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
            crash_client: client_sym,
        },
        tests: test_results,
    };

    let full_report_path = env.run_dir.join("full-report.json");
    let full_report_file = File::create(&full_report_path)?;
    serde_json::to_writer_pretty(full_report_file, &full_report)?;

    println!("full report written to: {}", full_report_path);
    println!();

    Ok(full_report)
}

/// Stage 5: launch the debugger on the test outputs
fn do_run_debugger(
    installed: &Utf8PathBuf,
    report: &FullReport,
    env: &BuildEnv,
) -> Result<(), PipelineError> {
    let viewable_dumps = report
        .tests
        .iter()
        .filter_map(|(_id, test)| test.dump.as_ref());

    let mut task = Command::new(installed);
    task.arg("--symbols-path").arg(&env.sym_dir);

    for dump in viewable_dumps {
        task.arg(dump);
    }

    println!("exec: {:?}", task);
    let status = task.status()?;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed to run minidump-debugger: {}",
            status.code().unwrap()
        )));
    }
    Ok(())
}

/// Stage 2: Run dump_syms on the crashing app's build dir to get symbols
fn do_dump_syms(
    dump_syms: &Utf8PathBuf,
    app: &Utf8PathBuf,
    env: &BuildEnv,
    enable_inlines: bool,
) -> Result<Utf8PathBuf, PipelineError> {
    println!("running dump_syms on {app}");

    let mut command = Command::new(dump_syms);

    // Optionally emit the (enormous) inlinee info
    if enable_inlines {
        command.arg("--inlines");
    }

    if cfg!(target_os = "macos") {
        // On macos we need to really hold dump_sym's hand to get most debuginfo
        let mut dsym = app.clone();
        dsym.set_extension("dSYM");
        command.arg("--type").arg("macho").arg(&dsym).arg(app);
    } else {
        command.arg(app);
    }

    println!("exec: {:?}", command);
    let output = command.output()?;

    let status = output.status;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed dump_syms: {}",
            status.code().unwrap()
        )));
    }

    // Slightly parse the file to get the debug_id and debug_file we need for the sym's path.

    // Format:
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

    // syms/DEBUG_FILE.ext/DEBUG_ID/DEBUG_FILE.sym
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

/// Get the test-suite from the crashing app
fn do_get_suite(app: &Utf8PathBuf) -> Result<Vec<TestKey>, PipelineError> {
    println!("getting test suite");
    let mut command = Command::new(app);
    command.arg("--list");

    println!("exec: {:?}", command);
    let output = command.output()?;

    let status = output.status;
    if !status.success() {
        return Err(PipelineError::Other(format!(
            "failed to get suite listing: {}",
            status.code().unwrap()
        )));
    }

    let stdout = String::from_utf8(output.stdout)?;
    let listing = stdout
        .lines()
        .map(|s| TestKey {
            signal: s.to_owned(),
            id: s.to_owned(),
        })
        .collect::<Vec<_>>();
    println!("got test suite!");
    for item in &listing {
        println!("  {}", item.id);
    }
    println!();

    Ok(listing)
}

/// Stage 3: run the app and crash, producing a .dmp
fn do_run_app(
    app: &Utf8PathBuf,
    env: &BuildEnv,
    test: &TestKey,
) -> Result<Utf8PathBuf, PipelineError> {
    println!("running app --signal={}", test.signal);
    let dump_path = env.dump_dir.join(format!("{}.dmp", test.id));

    let mut command = Command::new(app);
    command
        .arg("--signal")
        .arg(&test.signal)
        .arg("--dump")
        .arg(&dump_path);

    println!("exec: {:?}", command);
    let mut task = command.spawn()?;
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

/// Stage 4: process the minidump with symbols from Stage 2
fn do_minidump_stackwalk(
    mdsw: &Utf8PathBuf,
    minidump: &Utf8PathBuf,
    env: &BuildEnv,
    test: &TestKey,
) -> Result<MinidumpStackwalkOutput, PipelineError> {
    println!("running minidump-stackwalk");
    let json_report = env.report_dir.join(format!("{}.json", test.id));
    let human_report = env.report_dir.join(format!("{}.human.txt", test.id));
    let logs = env.report_dir.join(format!("{}.log.txt", test.id));

    let mut command = Command::new(mdsw);
    command
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
        .arg(minidump);

    println!("exec: {:?}", command);
    let mut task = command.spawn()?;
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

/// Stage 1: build+install a binary
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

    if dep.force_build {
        // Get ALL that debuginfo, we're building for dumpsyms!
        let mut rustflags = String::new();

        // Make sure we get debuginfo
        rustflags.push_str(" -Cdebuginfo=2");

        // Macos wants us to emit a dSYM for dumpsyms
        if cfg!(target_os = "macos") {
            rustflags.push_str(" -Csplit-debuginfo=packed");
        }
        if let Some(rust_mangling) = &env.rust_mangling {
            use std::fmt::Write;
            write!(rustflags, " -Csymbol-mangling-version={}", rust_mangling).unwrap();
        }

        command.env("RUSTFLAGS", rustflags);
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

    command
        .arg("--message-format=json")
        .stdout(std::process::Stdio::piped());

    println!("exec: {:?}", command);
    let mut task = command.spawn()?;

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
        let mut command = Command::new("cargo");
        command
            .arg("install")
            .arg("--list")
            .arg("--root")
            .arg(&env.install_dir);

        println!("exec: {:?}", command);
        let output = command.output()?;

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
                        let path = env.real_install_dir.join(bin.trim());
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
        let installed = env.real_install_dir.join(bin_name);
        std::fs::copy(&orig_bin_path, &installed)?;
        return Ok(InstallOutput {
            installed,
            orig_bin_path: Some(orig_bin_path),
        });
    }

    Err(PipelineError::Other("failed to find binary!".to_string()))
}
