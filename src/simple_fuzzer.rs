use core::time::Duration;
use std::{env, fmt::Write, fs, io, path::PathBuf, ptr::NonNull, process};
use clap::{builder::Str, Parser};
// use std::{env, fmt::Write, fs::DirEntry, io, path::PathBuf, process};
use env_logger::Builder;

// use core::time::Duration;
// use std::{env, path::PathBuf, process};

use libafl::{corpus::{InMemoryCorpus, OnDiskCorpus, InMemoryOnDiskCorpus}, feedbacks::MaxMapFeedback, observers::CanTrack, Fuzzer};
// use libafl::state::HasExecutions;
// #[allow(unused_imports)]
use libafl::{
    corpus::{Corpus},
    events::{
        SimpleEventManager, SimpleRestartingEventManager, launcher::Launcher, ClientDescription, LlmpRestartingEventManager,
    },
    feedbacks::{
        CrashFeedback,
        TimeoutFeedback,
        TimeFeedback
    },
    observers::{
        HitcountsMapObserver,
        ConstMapObserver,
        VariableMapObserver,
        TimeObserver
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
        StdMutationalStage,
    },
    feedback_or,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, tokens_mutations, scheduled::HavocScheduledMutator, token_mutations::I2SRandReplace},
    executors::{ExitKind, ShadowExecutor, forkserver::SHM_CMPLOG_ENV_VAR},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    // schedulers::QueueScheduler,
    state::{HasCorpus, StdState},
    Error,
};

use libafl_bolts::AsSliceMut;
// #[allow(unused_imports)]
use libafl_bolts::{
    current_time,
    ownedref::OwnedMutSlice,
    core_affinity::Cores,
    os::unix_signals::Signal,
    shmem::{ShMem, ShMemProvider, StdShMemProvider, UnixShMemProvider},
    rands::StdRand,
    tuples::{tuple_list, Handled, Merge},
    AsSlice,
};

use libafl_qemu::{
    breakpoint::Breakpoint, elf::EasyElf, modules::{
        cmplog::{CmpLogChildModule, CmpLogObserver},
        edges::StdEdgeCoverageChildModule,
        EmulatorModuleTuple
    }, qemu, ArchExtras, Emulator, GuestAddr, GuestReg, MmapPerms, Qemu, QemuExecutor, QemuExitError, QemuExitReason, QemuForkExecutor, QemuMappingsViewer, QemuMemoryChunk, QemuRWError, QemuShutdownCause, Regs, TargetSignalHandling
    // StdEmulatorDriver,
};

use libafl_targets::{edges_map_mut_ptr, CmpLogMap, CMPLOG_MAP_PTR, EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_ALLOCATED_SIZE, MAX_EDGES_FOUND};

const MAX_INPUT_SIZE: usize = 1048576; // 1MB
const MAP_SIZE: usize = 65536;

#[derive(Default)]
pub struct Version;

fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
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

pub fn fuzz() -> Result<(), Error> {
    #![allow(unused_mut)]
    #![allow(unused_variables)]
    #![allow(unreachable_code)]
    let mut builder = Builder::from_default_env();
    // unsafe {
    //     env::remove_var("LD_LIBRARY_PATH");
    // }
    let mut log_level: log::LevelFilter = log::LevelFilter::Warn;
    let mut cli_args = FuzzerArgs::parse();

    if cli_args.verbose {
        log_level = log::LevelFilter::Debug;
    }
    builder
        .filter(None, log_level)
        .init();

    let corpus_files = cli_args
        .input_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .collect::<Result<Vec<fs::DirEntry>, io::Error>>()
        .expect("Failed to read dir entry");

        let in_dir = [PathBuf::from(cli_args.input_dir)];


    let program = env::args().next().unwrap();
    log::info!("Program: {program:}");

    cli_args.args.insert(0, program);
    log::info!("ARGS: {:#?}", cli_args.args);

    let mut shmem_provider = StdShMemProvider::new().unwrap();


    // let mut cmplog_shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // unsafe {
    //     cmplog_shmem.write_to_env(SHM_CMPLOG_ENV_VAR).unwrap();
    // }
    // let cmpmap: &mut [u8; MAP_SIZE] = cmplog_shmem
    //     .as_slice_mut()
    //     .try_into()
    //     .expect("could not convert slice to sized slice.");

   

    // let mut edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
    //     "shared_mem",
    //     cmpmap,
    // ));

    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_DEFAULT_SIZE).unwrap();
    let edges = edges_shmem.as_slice_mut();
    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
            "edges",
            NonNull::new(edges.as_mut_ptr())
                .expect("map ptr is null.")
                .cast::<[u8; EDGES_MAP_DEFAULT_SIZE]>(),
        ))
        .track_indices()
    };
    // let mut edges_observer = unsafe {
    //     HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
    //         "edges",
    //         OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_ALLOCATED_SIZE),
    //         &raw mut MAX_EDGES_FOUND,
    //     ))
    //     .track_indices()
    // };
    let emulator_modules = tuple_list!(
        StdEdgeCoverageChildModule::builder()
            .const_map_observer(edges_observer.as_mut())
            .build()?,
        CmpLogChildModule::default(),
    );
    // let emulator_modules = tuple_list!(
    //     StdEdgeCoverageModule::builder()
    //         .map_observer(edges_observer.as_mut())
    //         .build()
    //         .unwrap(),
    //     CmpLogModule::default()
    // );

    // let mut qemu_args: Vec<String> = Vec::new();
    // qemu_args.push(String::from("./target/debug/go_lib"));
    // // qemu_args.push(String::from("-L"));
    // // qemu_args.push(String::from("/home/dimeko/dev/go_lib_afl/go_lib/bin/tlib.so"));
    
    // qemu_args.push(String::from("./harness/harness"));
    // // qemu_args.push(String::from("-E"));
    // // qemu_args.push(String::from("LD_PRELOAD=/home/dimeko/dev/go_lib_afl/go_lib/bin/tlib.so"));
    // qemu_args.push(String::from("-E"));
    // qemu_args.push(String::from("LD_LIBRARY_PATH=/home/dimeko/dev/go_lib_afl/go_lib/bin/"));
    // // qemu_args.push(String::from("-L"));
    // // qemu_args.push(String::from("./go_lib/bin"));

    // for _args in qemu_args.iter() {
    //     log::info!("arg: {_args:?}");
    // }

    let emulator = Emulator::empty()
        .qemu_parameters(cli_args.args)
        .modules(emulator_modules)
        .build()
        .expect("QEMU init failed");
    // emulator.set_target_crash_handling(&TargetSignalHandling::RaiseSignal);

    let qemu = emulator.qemu();



    // let mut run_client = |
    //     state: Option<_>,
    //     mut manager: LlmpRestartingEventManager<_, _, _, _, _>,
    //     cdesc: ClientDescription| {


    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::info!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    qemu.entry_break(test_one_input_ptr); // LLVMFuzzerTestOneInput
    // unsafe {
    //     match qemu.run() {
    //         Ok(QemuExitReason::Breakpoint(_)) => {}
    //         _ => panic!("Unexpected QEMU exit."),
    //     }
    // }

    log::info!("Break at {:#x}", qemu.read_reg(Regs::Pc).unwrap());

    let stack_ptr: u64 = qemu.read_reg(Regs::Sp).unwrap();
    let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
    log::info!("Return address = {ret_addr:#x}");

    log::info!("Stack pointer = {stack_ptr:#x}");
    log::info!("Return address = {ret_addr:#x}");

    // qemu.remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    qemu.set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr
    let mappings = QemuMappingsViewer::new(&qemu);
    println!("{:#?}", mappings);
    let input_addr = qemu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    log::info!("Placing input at {input_addr:#x}");

    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut cmp_shmem = shmem_provider.uninit_on_shmem::<CmpLogMap>().unwrap();
    let cmplog = cmp_shmem.as_slice_mut();
    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    // let mut manager = SimpleEventManager::new(mon);


    let (state, mut manager) = match SimpleRestartingEventManager::launch(mon, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };
    // let (state, mut manager) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    // {
    //     // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    //     Ok(res) => res,
    //     Err(err) => match err {
    //         Error::ShuttingDown => {
    //             return Ok(());
    //         }
    //         _ => {
    //             panic!("Failed to setup the restarter: {err}");
    //         }
    //     },
    // };


    let time_observer = TimeObserver::new("time");
    // Beginning of a page should be properly aligned.
    #[expect(clippy::cast_ptr_alignment)]
    let cmplog_map_ptr = cmplog
        .as_mut_ptr()
        .cast::<libafl_qemu::modules::cmplog::CmpLogMap>();
    let cmplog_observer: CmpLogObserver = unsafe { CmpLogObserver::with_map_ptr("cmplog", cmplog_map_ptr, true) };

    // let mut feedback = MaxMapFeedback::new(&edges_observer);
        // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );
    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| { StdState::new(
            StdRand::new(),
            InMemoryOnDiskCorpus::new(PathBuf::from("./out/queue")).unwrap(),
            OnDiskCorpus::new(PathBuf::from("./out/solutions")).unwrap(),
            &mut feedback,
            &mut objective).unwrap()
    });

    let files = corpus_files
        .iter()
        .map(|x| x.path())
        .collect::<Vec<PathBuf>>();

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
    );    

        // Setup a randomic Input2State stage
        let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
            I2SRandReplace::new()
        )));

        let mutator =
            HavocScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);
    
        // Setup an havoc mutator with a mutational stage
        // let mutator = HavocScheduledMutator::new(havoc_mutations());
    
        let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
            StdPowerMutationalStage::new(mutator);
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        // let mut stages = tuple_list!(
        //     StdMutationalStage::new(mutator),
            
        // );

    let mut fuzzer = StdFuzzer::new(
        scheduler,
        feedback,
        objective
    );

    let mut harness = |_emu: &mut Emulator<_, _, _, _, _, _, _>,  input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > 4096 {
            buf = &buf[0..4096];
            len = 4096;
        }

        let _qemu = _emu.qemu();

        unsafe {

            _qemu.write_mem(input_addr, buf).expect(&format!("could not set input at {input_addr:?}"));

            _qemu.write_reg(Regs::Pc, test_one_input_ptr).expect(&format!("could not set PC register"));
            _qemu.write_reg(Regs::Sp, stack_ptr).expect(&format!("could not set SP register"));

            _qemu.write_return_address(ret_addr).expect(&format!("could not set return address"));
            _qemu.write_function_argument(0, input_addr).expect(&format!("could not set arg 1"));
            _qemu.write_function_argument(1, len as u64).expect(&format!("could not set arg 2"));
            // let qemu_ret = ;
            // log::info!("QEMU is running!");

            match _qemu.run() {
                Ok(QemuExitReason::Crash) => {
                    return ExitKind::Crash},
                Ok(QemuExitReason::Timeout) => {
                    return ExitKind::Timeout
                },
                Ok(QemuExitReason::Breakpoint(_)) => {
                    return ExitKind::Ok
                },
                Ok(QemuExitReason::SyncExit) => {
                    return ExitKind::Ok
                },
                Ok(QemuExitReason::End(QemuShutdownCause::GuestPanic)) => {
                    return ExitKind::Timeout
                },
                Err(QemuExitError::UnexpectedExit) => {
                    return ExitKind::Crash
                },
                Err(err) => panic!("Unexpected QEMU exit: {err:?}"),
                _ => panic!("Target crashed unexpectedly")
            }
            ExitKind::Ok
        }
        // let target = input.target_bytes();
        // let mut buf = target.as_slice();
        // let mut len = buf.len();
        // if len > 4096 {
        //     buf = &buf[0..4096];
        //     len = 4096;
        // }

        // unsafe {
        //     // # Safety
        //     // The input buffer size is checked above. We use `write_mem_unchecked` for performance reasons
        //     // For better error handling, use `write_mem` and handle the returned Result
        //     log::info!("input is: {:?}", buf);
        //     qemu.write_mem_unchecked(input_addr, buf);

        //     qemu.write_reg(Regs::Rdi, input_addr).unwrap();
        //     qemu.write_reg(Regs::Rsi, len as GuestReg).unwrap();
        //     qemu.write_reg(Regs::Rip, test_one_input_ptr).unwrap();
        //     qemu.write_reg(Regs::Rsp, stack_ptr).unwrap();

        //     match qemu.run() {
        //         Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
        //         Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
        //             signal.handle();
        //             panic!("Unexpected signal: {signal:?}");
        //         }
        //         Err(QemuExitError::UnexpectedExit) => ExitKind::Crash,
        //         _ => {
        //             panic!("Unexpected QEMU exit.")
        //         }
        //     }
        // }
        // ExitKind::Ok

    };



    let executor = QemuForkExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut manager,
        shmem_provider,
        Duration::from_millis(5000))
    .expect("Failed to create QemuExecutor");

    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut manager, &in_dir.clone())
            .unwrap_or_else(|err| {
                log::info!("Failed to load initial corpus: error: {:?}", err);
                process::exit(0);
            });
        log::info!("We imported {} inputs from disk.", state.corpus().count());
    }

    let tracing = ShadowTracingStage::new();


    let mut stages = tuple_list!(
        CalibrationStage::new(&calibration_feedback), tracing, i2s, power);


    log::info!("Processed {} inputs from disk.", files.len());
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager).expect("error in the fuzzing loop");
    // };
    Ok(())
}

// A singlethreaded QEMU fuzzer that can auto-restart.

// use core::cell::RefCell;
// #[cfg(unix)]
// use std::os::unix::io::{AsRawFd, FromRawFd};
// use std::{
//     env,
//     fs::{self, File, OpenOptions},
//     io::{self, Write},
//     path::PathBuf,
//     process,
//     ptr::NonNull,
//     time::Duration,
// };

// use clap::{Arg, Command};
// use libafl::{
//     corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
//     events::SimpleRestartingEventManager,
//     executors::{ExitKind, ShadowExecutor},
//     feedback_or,
//     feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
//     fuzzer::{Fuzzer, StdFuzzer},
//     inputs::{BytesInput, HasTargetBytes},
//     monitors::SimpleMonitor,
//     mutators::{
//         havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, HavocScheduledMutator,
//         StdMOptMutator, Tokens,
//     },
//     observers::{CanTrack, ConstMapObserver, HitcountsMapObserver, TimeObserver},
//     schedulers::{
//         powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
//     },
//     stages::{
//         calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
//         StdMutationalStage,
//     },
//     state::{HasCorpus, StdState},
//     Error, HasMetadata,
// };
// use libafl_bolts::{
//     current_time,
//     os::dup2,
//     rands::StdRand,
//     shmem::{ShMemProvider, StdShMemProvider},
//     tuples::{tuple_list, Merge},
//     AsSlice, AsSliceMut,
// };
// use libafl_qemu::{
//     elf::EasyElf,
//     filter_qemu_args,
//     modules::{
//         cmplog::{CmpLogChildModule, CmpLogMap, CmpLogObserver},
//         edges::StdEdgeCoverageChildModule,
//     },
//     Emulator, GuestReg, MmapPerms, QemuExitError, QemuExitReason, QemuForkExecutor,
//     QemuShutdownCause, Regs,
// };
// use libafl_targets::{CMPLOG_MAP_PTR, EDGES_MAP_DEFAULT_SIZE};
// // #[cfg(unix)]
// // use nix::unistd::dup;

// /// The fuzzer main
// pub fn main() {
//     // Registry the metadata types used in this fuzzer
//     // Needed only on no_std
//     // unsafe { RegistryBuilder::register::<Tokens>(); }

//     env_logger::init();

//     let res = match Command::new(env!("CARGO_PKG_NAME"))
//         .version(env!("CARGO_PKG_VERSION"))
//         .author("AFLplusplus team")
//         .about("LibAFL-based fuzzer with QEMU for Fuzzbench")
//         .arg(
//             Arg::new("out")
//                 .help("The directory to place finds in ('corpus')")
//                 .long("libafl-out")
//                 .required(true),
//         )
//         .arg(
//             Arg::new("in")
//                 .help("The directory to read initial inputs from ('seeds')")
//                 .long("libafl-in")
//                 .required(true),
//         )
//         .arg(
//             Arg::new("tokens")
//                 .long("libafl-tokens")
//                 .help("A file to read tokens from, to be used during fuzzing"),
//         )
//         .arg(
//             Arg::new("logfile")
//                 .long("libafl-logfile")
//                 .help("Duplicates all output to this file")
//                 .default_value("libafl.log"),
//         )
//         .try_get_matches_from(filter_qemu_args())
//     {
//         Ok(res) => res,
//         Err(err) => {
//             println!(
//                 "Syntax: {}, --libafl-in <input> --libafl-out <output>\n{:?}",
//                 env::current_exe()
//                     .unwrap_or_else(|_| "fuzzer".into())
//                     .to_string_lossy(),
//                 err,
//             );
//             return;
//         }
//     };

//     println!(
//         "Workdir: {:?}",
//         env::current_dir().unwrap().to_string_lossy().to_string()
//     );

//     // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
//     let mut out_dir = PathBuf::from(res.get_one::<String>("out").unwrap().to_string());
//     if fs::create_dir(&out_dir).is_err() {
//         println!("Out dir at {:?} already exists.", &out_dir);
//         if !out_dir.is_dir() {
//             println!("Out dir at {:?} is not a valid directory!", &out_dir);
//             return;
//         }
//     }
//     let mut crashes = out_dir.clone();
//     crashes.push("crashes");
//     out_dir.push("queue");

//     let in_dir = PathBuf::from(res.get_one::<String>("in").unwrap().to_string());
//     if !in_dir.is_dir() {
//         println!("In dir at {:?} is not a valid directory!", &in_dir);
//         return;
//     }

//     let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

//     let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());

//     fuzz(out_dir, crashes, in_dir, tokens, logfile).expect("An error occurred while fuzzing");
// }

// /// The actual fuzzer
// fn fuzz(
//     corpus_dir: PathBuf,
//     objective_dir: PathBuf,
//     seed_dir: PathBuf,
//     tokenfile: Option<PathBuf>,
//     logfile: PathBuf,
// ) -> Result<(), Error> {
//     // env::remove_var("LD_LIBRARY_PATH");

//     let args: Vec<String> = env::args().collect();

//     let mut shmem_provider = StdShMemProvider::new()?;

//     let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_DEFAULT_SIZE).unwrap();
//     let edges = edges_shmem.as_slice_mut();

//     // Create an observation channel using the coverage map
//     let mut edges_observer = unsafe {
//         HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
//             "edges",
//             NonNull::new(edges.as_mut_ptr())
//                 .expect("map ptr is null.")
//                 .cast::<[u8; EDGES_MAP_DEFAULT_SIZE]>(),
//         ))
//         .track_indices()
//     };

//     let emulator_modules = tuple_list!(
//         StdEdgeCoverageChildModule::builder()
//             .const_map_observer(edges_observer.as_mut())
//             .build()?,
//         CmpLogChildModule::default(),
//     );

//     let emulator = Emulator::empty()
//         .qemu_parameters(args)
//         .modules(emulator_modules)
//         .build()?;

//     let qemu = emulator.qemu();

//     let mut elf_buffer = Vec::new();
//     let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

//     let test_one_input_ptr = elf
//         .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
//         .expect("Symbol LLVMFuzzerTestOneInput not found");
//     println!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

//     qemu.set_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
//     unsafe {
//         match qemu.run() {
//             Ok(QemuExitReason::Breakpoint(_)) => {}
//             _ => panic!("Unexpected QEMU exit."),
//         }
//     }

//     println!("Break at {:#x}", qemu.read_reg(Regs::Pc).unwrap());

//     let stack_ptr: u64 = qemu.read_reg(Regs::Sp).unwrap();
//     let mut ret_addr = [0; 8];
//     qemu.read_mem(stack_ptr, &mut ret_addr)
//         .expect("qemu read failed");
//     let ret_addr = u64::from_le_bytes(ret_addr);

//     println!("Stack pointer = {stack_ptr:#x}");
//     println!("Return address = {ret_addr:#x}");

//     qemu.remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
//     qemu.set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

//     let input_addr = qemu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
//     println!("Placing input at {input_addr:#x}");

//     let log = RefCell::new(
//         OpenOptions::new()
//             .append(true)
//             .create(true)
//             .open(&logfile)?,
//     );

//     // #[cfg(unix)]
//     // let mut stdout_cpy = unsafe {
//     //     let new_fd = dup(io::stdout().as_raw_fd())?;
//     //     File::from_raw_fd(new_fd)
//     // };
//     // #[cfg(unix)]
//     // let file_null = File::open("/dev/null")?;

//     // // 'While the stats are state, they are usually used in the broker - which is likely never restarted
//     // let monitor = SimpleMonitor::new(|s| {
//     //     #[cfg(unix)]
//     //     writeln!(&mut stdout_cpy, "{s}").unwrap();
//     //     #[cfg(windows)]
//     //     println!("{s}");
//     //     writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
//     // });

//     let monitor = SimpleMonitor::new(|s| println!("{s}"));

//     let mut cmp_shmem = shmem_provider.uninit_on_shmem::<CmpLogMap>().unwrap();
//     let cmplog = cmp_shmem.as_slice_mut();

//     // Beginning of a page should be properly aligned.
//     #[expect(clippy::cast_ptr_alignment)]
//     let cmplog_map_ptr = cmplog
//         .as_mut_ptr()
//         .cast::<libafl_qemu::modules::cmplog::CmpLogMap>();

//     let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
//     {
//         // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
//         Ok(res) => res,
//         Err(err) => match err {
//             Error::ShuttingDown => {
//                 return Ok(());
//             }
//             _ => {
//                 panic!("Failed to setup the restarter: {err}");
//             }
//         },
//     };

//     // Create an observation channel to keep track of the execution time
//     let time_observer = TimeObserver::new("time");

//     // Create an observation channel using cmplog map
//     unsafe {
//         CMPLOG_MAP_PTR = cmplog_map_ptr;
//     }
//     let cmplog_observer = unsafe { CmpLogObserver::with_map_ptr("cmplog", cmplog_map_ptr, true) };

//     let map_feedback = MaxMapFeedback::new(&edges_observer);

//     let calibration = CalibrationStage::new(&map_feedback);

//     // Feedback to rate the interestingness of an input
//     // This one is composed by two Feedbacks in OR
//     let mut feedback = feedback_or!(
//         // New maximization map feedback linked to the edges observer and the feedback state
//         map_feedback,
//         // Time feedback, this one does not need a feedback state
//         TimeFeedback::new(&time_observer)
//     );

//     // A feedback to choose if an input is a solution or not
//     let mut objective = CrashFeedback::new();

//     // create a State from scratch
//     let mut state = state.unwrap_or_else(|| {
//         StdState::new(
//             // RNG
//             StdRand::new(),
//             // Corpus that will be evolved, we keep it in memory for performance
//             InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
//             // Corpus in which we store solutions (crashes in this example),
//             // on disk so the user can get them after stopping the fuzzer
//             OnDiskCorpus::new(objective_dir).unwrap(),
//             // States of the feedbacks.
//             // The feedbacks can report the data that should persist in the State.
//             &mut feedback,
//             // Same for objective feedbacks
//             &mut objective,
//         )
//         .unwrap()
//     });

//     // Setup a randomic Input2State stage
//     let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
//         I2SRandReplace::new()
//     )));

//     // Setup a MOPT mutator
//     let mutator = StdMOptMutator::new(
//         &mut state,
//         havoc_mutations().merge(tokens_mutations()),
//         7,
//         5,
//     )?;

//     let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
//         StdPowerMutationalStage::new(mutator);

//     // A minimization+queue policy to get testcasess from the corpus
//     let scheduler = IndexesLenTimeMinimizerScheduler::new(
//         &edges_observer,
//         PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
//     );

//     // A fuzzer with feedbacks and a corpus scheduler
//     let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

//     // The wrapped harness function, calling out to the LLVM-style harness
//     let mut harness = |_emulator: &mut Emulator<_, _, _, _, _, _, _>, input: &BytesInput| {
//         let target = input.target_bytes();
//         let mut buf = target.as_slice();
//         let mut len = buf.len();
//         if len > 4096 {
//             buf = &buf[0..4096];
//             len = 4096;
//         }

//         unsafe {
//             // # Safety
//             // The input buffer size is checked above. We use `write_mem_unchecked` for performance reasons
//             // For better error handling, use `write_mem` and handle the returned Result
//             qemu.write_mem_unchecked(input_addr, buf);

//             qemu.write_reg(Regs::Rdi, input_addr).unwrap();
//             qemu.write_reg(Regs::Rsi, len as GuestReg).unwrap();
//             qemu.write_reg(Regs::Rip, test_one_input_ptr).unwrap();
//             qemu.write_reg(Regs::Rsp, stack_ptr).unwrap();

//             match qemu.run() {
//                 Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
//                 Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
//                     signal.handle();
//                     panic!("Unexpected signal: {signal:?}");
//                 }
//                 Err(QemuExitError::UnexpectedExit) => ExitKind::Crash,
//                 _ => {
//                     panic!("Unexpected QEMU exit.")
//                 }
//             }
//         }
//     };

//     let executor = QemuForkExecutor::new(
//         emulator,
//         &mut harness,
//         tuple_list!(edges_observer, time_observer),
//         &mut fuzzer,
//         &mut state,
//         &mut mgr,
//         shmem_provider,
//         Duration::from_millis(5000),
//     )?;

//     // Show the cmplog observer
//     let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

//     // Read tokens
//     if let Some(tokenfile) = tokenfile {
//         if state.metadata_map().get::<Tokens>().is_none() {
//             state.add_metadata(Tokens::from_file(tokenfile)?);
//         }
//     }

//     if state.must_load_initial_inputs() {
//         state
//             .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
//             .unwrap_or_else(|_| {
//                 println!("Failed to load initial corpus at {:?}", &seed_dir);
//                 process::exit(0);
//             });
//         println!("We imported {} inputs from disk.", state.corpus().count());
//     }

//     let tracing = ShadowTracingStage::new();

//     // The order of the stages matter!
//     let mut stages = tuple_list!(calibration, tracing, i2s, power);

//     // Remove target output (logs still survive)
//     // #[cfg(unix)]
//     // {
//     //     let null_fd = file_null.as_raw_fd();
//     //     dup2(null_fd, io::stdout().as_raw_fd())?;
//     //     dup2(null_fd, io::stderr().as_raw_fd())?;
//     // }
//     // reopen file to make sure we're at the end
//     log.replace(
//         OpenOptions::new()
//             .append(true)
//             .create(true)
//             .open(&logfile)?,
//     );

//     fuzzer
//         .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
//         .expect("Error in the fuzzing loop");

//     // Never reached
//     Ok(())
// }
