use std::{error::Error, path::PathBuf, sync::atomic::AtomicBool};

static ID: &str = "1234";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();
    let _bin_name = args.next().unwrap();
    if let Some(arg1) = args.next() {
        if arg1 == "--crash-monitor" {
            let dump_path = PathBuf::from(args.next().unwrap());
            crash_monitor_main(dump_path)?;
        } else {
            let id = arg1;
            app_main(&id)?;
        }
    }

    Ok(())
}

fn crash_monitor_main(dump_path: PathBuf) -> Result<(), Box<dyn Error>> {
    println!("monitor: starting crash monitor...");

    struct MyServer {
        id: String,
        dump_path: PathBuf,
    }

    impl minidumper::ServerHandler for MyServer {
        fn create_minidump_file(&self) -> Result<(std::fs::File, PathBuf), std::io::Error> {
            println!("monitor: making dump file!");

            let file = std::fs::File::create(&self.dump_path)?;

            Ok((file, self.dump_path.to_owned()))
        }

        fn on_minidump_created(
            &self,
            result: Result<minidumper::MinidumpBinary, minidumper::Error>,
        ) -> minidumper::LoopAction {
            println!("monitor: yay dump!");
            minidumper::LoopAction::Exit
        }

        fn on_message(&self, _kind: u32, _buffer: Vec<u8>) {
            unreachable!("monitor: we only test crashes");
        }
    }

    let conn_id = ID;
    let cur_bin = std::env::current_exe()?;
    let app = std::process::Command::new(&cur_bin).arg(conn_id).spawn()?;

    let shutdown = AtomicBool::new(false);
    let mut server = minidumper::Server::with_name(conn_id)?;
    let handler = Box::new(MyServer {
        id: conn_id.to_owned(),
        dump_path,
    });
    server.run(handler, &shutdown, None)?;

    Ok(())
}

fn app_main(conn_id: &str) -> Result<(), Box<dyn Error>> {
    println!("app: starting app...");

    let start = std::time::Instant::now();
    let connect_timeout = std::time::Duration::from_secs(2);

    let md_client = loop {
        match minidumper::Client::with_name(conn_id) {
            Ok(md_client) => break md_client,
            Err(e) => {
                if std::time::Instant::now() - start > connect_timeout {
                    panic!("timed out trying to connect to server process: {:#}", e);
                }
            }
        }
    };

    let _handler = crash_handler::CrashHandler::attach(unsafe {
        crash_handler::make_crash_event(move |cc: &crash_handler::CrashContext| {
            println!("app: requesting dump!");
            let handled = md_client.request_dump(cc).is_ok();
            crash_handler::CrashEventResult::Handled(handled)
        })
    });

    println!("app: started!");

    println!("app: time to fail!");
    too_big_stack(&[9]);
    // assert!(false);

    Ok(())
}

fn too_big_stack(val: &[i32]) {
    let x = [0; 1000_0000];
    too_big_stack(&x);
}
