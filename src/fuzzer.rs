// use core::fmt::Debug;

use core::time::Duration;
use std::{env, fmt::Write, fs, io, path::PathBuf, process};
use clap::{builder::Str, Parser};
// use std::{env, fmt::Write, fs::DirEntry, io, path::PathBuf, process};
use env_logger::Builder;

// use core::time::Duration;
// use std::{env, path::PathBuf, process};

// use libafl::state::HasExecutions;
#[allow(unused_imports)]
use libafl::{
    corpus::{Corpus, InMemoryCorpus},
    events::{
        launcher::Launcher, ClientDescription, EventConfig, LlmpRestartingEventManager, SendExiting,
    },
    executors::ExitKind,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    schedulers::QueueScheduler,
    state::{HasCorpus, StdState},
    Error,
};

use libafl_bolts::{
    core_affinity::Cores,
    os::unix_signals::Signal,
    shmem::{ShMemProvider, StdShMemProvider},
    rands::StdRand,
    tuples::tuple_list,
    AsSlice,
};

use libafl_qemu::{
    elf::EasyElf,
    modules::{drcov::DrCovModule, SnapshotModule},
    ArchExtras, Emulator, GuestAddr, GuestReg, MmapPerms, Qemu, QemuExecutor, QemuExitReason,
    QemuMappingsViewer, QemuRWError, QemuShutdownCause, Regs,
    // StdEmulatorDriver,
};
// use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
// pub type ClientState =
//     StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

// fn get_emulator<C, ET, I, S>(
//     args: Vec<String>,
//     mut modules: ET,
// ) -> Result<
//     Emulator<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, NopSnapshotManager>,
//     QemuInitError,
// >
// where
//     ET: EmulatorModuleTuple<I, S> + HasAddressFilterTuple,
//     I: HasTargetBytes + Unpin,
//     S: HasExecutions + Unpin,
// {
//     // Allow linux process address space addresses as feedback
//     modules.allow_address_range_all(&LINUX_PROCESS_ADDRESS_RANGE);

//     Emulator::builder()
//         .qemu_parameters(args)
//         .modules(modules)
//         .build()
// }
pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

#[derive(Default)]
pub struct Version;

fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

impl From<Version> for Str {
    fn from(_: Version) -> Str {
        let version = [
            ("Architecture:", env!("CPU_TARGET")),
            ("Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP")),
            ("Describe:", env!("VERGEN_GIT_DESCRIBE")),
            ("Commit SHA:", env!("VERGEN_GIT_SHA")),
            ("Commit Date:", env!("VERGEN_RUSTC_COMMIT_DATE")),
            ("Commit Branch:", env!("VERGEN_GIT_BRANCH")),
            ("Rustc Version:", env!("VERGEN_RUSTC_SEMVER")),
            ("Rustc Channel:", env!("VERGEN_RUSTC_CHANNEL")),
            ("Rustc Host Triple:", env!("VERGEN_RUSTC_HOST_TRIPLE")),
            ("Rustc Commit SHA:", env!("VERGEN_RUSTC_COMMIT_HASH")),
            ("Cargo Target Triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ]
        .iter()
        .fold(String::new(), |mut output, (k, v)| {
            let _ = writeln!(output, "{k:25}: {v}");
            output
        });

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu_coverage-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Module for generating DrCov coverage data using QEMU instrumentation"
)]
pub struct FuzzerArgs {
    #[arg(long, help = "Coverage file")]
    coverage_path: PathBuf,

    #[arg(long, help = "Input directory")]
    input_dir: PathBuf,

    #[arg(long, help = "Timeout in seconds", default_value = "5000", value_parser = timeout_from_millis_str)]
    timeout: Duration,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub fn fuzz() {
    // #![allow(unused_mut)]
    // #![allow(unused_variables)]
    // #![allow(unreachable_code)]

    let mut builder = Builder::from_default_env();

    let mut log_level: log::LevelFilter = log::LevelFilter::Warn;
    let cli_args = FuzzerArgs::parse();

    if cli_args.verbose {
        log_level = log::LevelFilter::Debug;
    }
    builder
        .filter(None, log_level)
        .init();

    let mut options = FuzzerArgs::parse();

    // let timeout = Duration::from_secs(50);
    // let broker_port = 1338;
    // let cores = Cores::from_cmdline("1").unwrap();

    // let corpus_dir = fs::read_dir("./corpus").unwrap();
    
    // let corpus_dirs = corpus_dir.collect::<Result<Vec<fs::DirEntry>, io::Error>>()
    //     .expect("could not parse corpus dir");
    let corpus_files = options
        .input_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .collect::<Result<Vec<fs::DirEntry>, io::Error>>()
        .expect("Failed to read dir entry");
    // let objective_dir = PathBuf::from("./crashes");
    
    // let corpus_files: Vec<fs::DirEntry> = corpus_dirs.iter().map(|d| {
    //     return d.read_dir()
    //     .expect("Failed to read corpus dir")
    //     .collect::<Result<Vec<fs::DirEntry>, io::Error>>()
    //     .expect("Failed to read dir entry");
    // }).collect().;
    let num_files = corpus_files.len();
    let num_cores = options.cores.ids.len();
    let files_per_core = (num_files as f64 / num_cores as f64).ceil() as usize;

    let program = env::args().next().unwrap();
    log::info!("Program: {program:}");

    options.args.insert(0, program);
    log::info!("ARGS: {:#?}", options.args);

    unsafe { env::remove_var("LD_LIBRARY_PATH") };

    let mut run_client = |state: Option<_>,
        mut mgr: LlmpRestartingEventManager<_, _, _, _, _>,
        client_description: ClientDescription| {
            let mut cov_path = options.coverage_path.clone();
            let core_id = client_description.core_id();
    
            let coverage_name = cov_path.file_stem().unwrap().to_str().unwrap();
            let coverage_extension = cov_path.extension().unwrap_or_default().to_str().unwrap();
            let core = core_id.0;
            cov_path.set_file_name(format!("{coverage_name}-{core:03}.{coverage_extension}"));
    
            let emulator_modules = tuple_list!(
                DrCovModule::builder().filename(cov_path.clone()).build(),
                SnapshotModule::new(),
            );
    
            let emulator = Emulator::empty()
                .qemu_parameters(options.args.clone())
                .modules(emulator_modules)
                .build()
                .expect("QEMU initialization failed");
            let qemu = emulator.qemu();
    
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).unwrap();
    
            let test_one_input_ptr = elf
                .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
                .expect("Symbol LLVMFuzzerTestOneInput not found");
            log::info!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");
    
            qemu.entry_break(test_one_input_ptr);
    
            let mappings = QemuMappingsViewer::new(&qemu);
            println!("{:#?}", mappings);
    
            let pc: GuestReg = qemu.read_reg(Regs::Pc).unwrap();
            log::info!("Break at {pc:#x}");
    
            let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
            log::info!("Return address = {ret_addr:#x}");
    
            qemu.set_breakpoint(ret_addr);
    
            let input_addr = qemu
                .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
                .unwrap();
            log::info!("Placing input at {input_addr:#x}");
    
            let stack_ptr: GuestAddr = qemu.read_reg(Regs::Sp).unwrap();
    
            let reset = |qemu: Qemu, buf: &[u8], len: GuestReg| -> Result<(), QemuRWError> {
                unsafe {
                    log::info!("Input buf: {:?}", buf);
                    qemu.write_mem(input_addr, buf)?;
                    qemu.write_reg(Regs::Pc, test_one_input_ptr)?;
                    qemu.write_reg(Regs::Sp, stack_ptr)?;
                    qemu.write_return_address(ret_addr)?;
                    qemu.write_function_argument(0, input_addr)?;
                    qemu.write_function_argument(1, len)?;
    
                    match qemu.run() {
                        Ok(QemuExitReason::Breakpoint(_)) => {}
                        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(
                            Signal::SigInterrupt,
                        ))) => process::exit(0),
                        _ => panic!("Unexpected QEMU exit."),
                    }
    
                    Ok(())
                }
            };
    
            let mut harness =
                |emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
                    let qemu = emulator.qemu();
    
                    let target = input.target_bytes();
                    log::info!("Input target buf: {:?}", target);
                    let mut buf = target.as_slice();
                    let mut len = buf.len();
                    if len > MAX_INPUT_SIZE {
                        buf = &buf[0..MAX_INPUT_SIZE];
                        len = MAX_INPUT_SIZE;
                    }
                    let len = len as GuestReg;
                    reset(qemu, buf, len).unwrap();
    
                    ExitKind::Ok
                };
    
            let core_id = client_description.core_id();
            let core_idx = options
                .cores
                .position(core_id)
                .expect("Failed to get core index");
    
            let files = corpus_files
                .iter()
                .skip(files_per_core * core_idx)
                .take(files_per_core)
                .map(|x| x.path())
                .collect::<Vec<PathBuf>>();
            // for v in files.iter() {
            //     print!("de: {:?}", v);
            // }
            // process::exit(1);
            if files.is_empty() {
                log::error!("Empty corpus!");

                mgr.send_exiting()?;
                Err(Error::ShuttingDown)?
            }
    
            let mut feedback = ();
    
            let mut objective = ();
    
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    StdRand::new(),
                    InMemoryCorpus::new(),
                    InMemoryCorpus::new(),
                    &mut feedback,
                    &mut objective,
                )
                .unwrap()
            });
    
            let scheduler = QueueScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            log::info!("Initializing executor!");
            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness,
                (),
                &mut fuzzer,
                &mut state,
                &mut mgr,
                options.timeout,
            )
            .expect("Failed to create QemuExecutor");
    
            if state.must_load_initial_inputs() {
                state
                    .load_initial_inputs_by_filenames(&mut fuzzer, &mut executor, &mut mgr, &files)
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {:?}", &options.input_dir);
                        process::exit(0);
                    });
                log::info!("We imported {} inputs from disk.", state.corpus().count());
            }
    
            log::info!("Processed {} inputs from disk.", files.len());
    
            mgr.send_exiting()?;
            Err(Error::ShuttingDown)?
    };

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().expect("Failed to init shared memory"))
        .broker_port(options.port)
        .configuration(EventConfig::from_build_id())
        .monitor(MultiMonitor::new(|s| println!("{s}")))
        .run_client(&mut run_client)
        .cores(&options.cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Run finished successfully."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
    // // If not restarting, create a State from scratch
    // let mut state = match  {
    //     Some(x) => x,
    //     None => {
    //         StdState::new(
    //             // RNG
    //             StdRand::new(),
    //             // Corpus that will be evolved, we keep it in memory for performance
    //             InMemoryOnDiskCorpus::no_meta(
    //                 self.options.queue_dir(self.client_description.clone()),
    //             )?,
    //             // Corpus in which we store solutions (crashes in this example),
    //             // on disk so the user can get them after stopping the fuzzer
    //             OnDiskCorpus::new(self.options.crashes_dir(self.client_description.clone()))?,
    //             // States of the feedbacks.
    //             // The feedbacks can report the data that should persist in the State.
    //             &mut feedback,
    //             // Same for objective feedbacks
    //             &mut objective,
    //         )?
    //     }
    // };
    // let stats_stage = IfStage::new(
    //     |_, _, _, _| Ok(self.options.tui),
    //     tuple_list!(AflStatsStage::builder()
    //         .map_observer(&edges_observer)
    //         .build()?),
    // );
    // let stats_stage_cmplog = IfStage::new(
    //     |_, _, _, _| Ok(self.options.tui),
    //     tuple_list!(AflStatsStage::builder()
    //         .map_observer(&edges_observer)
    //         .build()?),
    // );

    // // The stats reporter for the broker
    // let monitor = MultiMonitor::new(|s| println!("{s}"));

    // // let monitor = SimpleMonitor::new(|s| println!("{s}"));
    // // let mut mgr = SimpleEventManager::new(monitor);
    // // run_client(None, mgr, 0);

    // // Build and run a Launcher
    // match Launcher::builder()
    //     .shmem_provider(shmem_provider)
    //     .broker_port(broker_port)
    //     .configuration(EventConfig::from_build_id())
    //     .monitor(monitor)
    //     .run_client(&mut run_client)
    //     .cores(&cores)
    //     // .stdout_file(Some("/dev/null"))
    //     .build()
    //     .launch()
    // {
    //     Ok(()) => (),
    //     Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
    //     Err(err) => panic!("Failed to run launcher: {err:?}"),
    // }
    // println!("fuzzer working");
}