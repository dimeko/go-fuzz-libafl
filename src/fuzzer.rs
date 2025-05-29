use core::time::Duration;
use std::{env, fs, io::{Read}, path::{PathBuf}, ptr::NonNull};
use clap::{Parser};
use env_logger::Builder;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    feedbacks::MaxMapFeedback,
    observers::{CanTrack},
    stages::{StdMutationalStage},
    Evaluator,
    Fuzzer};

use libafl::{
    events::
        SimpleRestartingEventManager
    ,
    feedbacks::{
        CrashFeedback,
        TimeFeedback
    },
    observers::{
        HitcountsMapObserver,
        ConstMapObserver,
        TimeObserver
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, ShadowTracingStage,
    },
    feedback_or,
    Error,
    monitors::SimpleMonitor,
    mutators::{scheduled::HavocScheduledMutator},
    executors::{ExitKind, ShadowExecutor},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    // schedulers::QueueScheduler,
    state::{StdState},
};

use libafl_bolts::{AsSliceMut};
// #[allow(unused_imports)]
use libafl_bolts::{
    shmem::{ShMemProvider, StdShMemProvider},
    rands::StdRand,
    tuples::{tuple_list},
    AsSlice,
};
use libafl_qemu::{
    elf::EasyElf, modules::{
    cmplog::{CmpLogChildModule, CmpLogObserver},
    edges::StdEdgeCoverageChildModule},
    ArchExtras,
    Emulator,
    GuestAddr,
    MmapPerms,
    QemuExitError,
    QemuExitReason,
    QemuForkExecutor,
    QemuMappingsViewer,
    QemuShutdownCause,
    Regs
};
use libafl_targets::{CMPLOG_MAP_PTR, EDGES_MAP_DEFAULT_SIZE};
use libafl_targets::{CmpLogMap};

use crate::mutators::JsonMutator;
// use crate::mutators::RandomResizeMutator;
use crate::mutators::RandomAsciiCharsMutator;

#[derive(Default)]
pub struct Version;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct FuzzerArgs {
    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub fn fuzz() -> Result<(), Error> {
    let mut builder = Builder::from_default_env();

    let mut log_level: log::LevelFilter = log::LevelFilter::Warn;
    let mut cli_args = FuzzerArgs::parse();

    if cli_args.verbose {
        log_level = log::LevelFilter::Debug;
    }
    builder
        .filter(None, log_level)
        .init();

    let mut initial_inputs = vec![];

    // Prepare the initial corpus in byte vectors 
    for entry in fs::read_dir("./json_corpus").unwrap() {
        let path = entry.unwrap().path();
        let attr = fs::metadata(&path);
        if attr.is_err() {
            continue;
        }
        let attr = attr.unwrap();

        if attr.is_file() && attr.len() > 0 {
            println!("Loading file {:?} ...", &path);
            let mut file = fs::File::open(path).expect("no file found");
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).expect("buffer overflow");
            let input: libafl::inputs::ValueInput<Vec<u8>> = BytesInput::new(buffer);
            initial_inputs.push(input);
        }
    }

    let program = env::args().next().unwrap();
    log::info!("Program: {program:}");

    cli_args.args.insert(0, program.clone());
    log::info!("ARGS: {:#?}", cli_args.args);

    // This is the basic shared memory provider which is going to provide shared memory 
    // for different components of the fuzzer
    let mut shmem_provider = StdShMemProvider::new().unwrap();

    // First shared memory region is needed for the edges observer
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

    // Initialize the emulator modules
    let emulator_modules = tuple_list!(
        StdEdgeCoverageChildModule::builder()
            .const_map_observer(edges_observer.as_mut())
            .build()?,
        CmpLogChildModule::default(),
    );

    // Initialize the emulator
    let emulator = Emulator::empty()
        .qemu_parameters(cli_args.args)
        .modules(emulator_modules)
        .build()
        .expect("QEMU init failed");

    let qemu = emulator.qemu();

    // Load the elf in fuzzer memory and start setting breakpoints
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

    // 1. breakpoint 
    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::info!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    qemu.entry_break(test_one_input_ptr);
    log::info!("Break at {:#x}", qemu.read_reg(Regs::Pc).unwrap());

    let stack_ptr: u64 = qemu.read_reg(Regs::Sp).unwrap();
    let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
    log::info!("Return address = {ret_addr:#x}");

    log::info!("Stack pointer = {stack_ptr:#x}");
    log::info!("Return address = {ret_addr:#x}");

    // 2. breakpoint 
    qemu.set_breakpoint(ret_addr);

    // List mappings in order to make sure the go shared library has been loaded into Qemu memory
    let mappings = QemuMappingsViewer::new(&qemu);
    println!("{:#?}", mappings);
    let input_addr = qemu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    log::info!("Placing input at {input_addr:#x}");

    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut cmp_shmem = shmem_provider.uninit_on_shmem::<CmpLogMap>().unwrap();
    let cmplog = cmp_shmem.as_slice_mut();

    let (state, mut manager) = match SimpleRestartingEventManager::launch(mon, &mut shmem_provider)
    {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to restart: {err}");
            }
        },
    };

    let time_observer = TimeObserver::new("time");

    #[expect(clippy::cast_ptr_alignment)]
    let cmplog_map_ptr = cmplog
        .as_mut_ptr()
        .cast::<libafl_qemu::modules::cmplog::CmpLogMap>();

    // Setting the CMPLOG_MAP_PTR is very important since this is the way
    // Qemu will provide us with the CmpLogs results.
    unsafe {
        CMPLOG_MAP_PTR = cmplog_map_ptr;
    }
    let cmplog_observer: CmpLogObserver = unsafe { CmpLogObserver::with_map_ptr("cmplog", cmplog_map_ptr, true) };

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );
    let mut objective = CrashFeedback::new();

    // TODO: add input and output directories in cli arguments
    let mut state = state.unwrap_or_else(|| { StdState::new(
            StdRand::new(),
            InMemoryOnDiskCorpus::new(PathBuf::from("./out/queue")).unwrap(),
            OnDiskCorpus::new(PathBuf::from("./out/solutions")).unwrap(),
            &mut feedback,
            &mut objective).unwrap()
    });

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
    );

    // Input mutator 1
    let json_mut = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        JsonMutator::new()
    )));

    // let random_mut = StdMutationalStage::new(RandomResizeMutator::new());
    // Input mutator 2
    let random_ascii_mut = StdMutationalStage::new(RandomAsciiCharsMutator::new());

    let tracing = ShadowTracingStage::new();

    let calibration_feedback = MaxMapFeedback::new(&edges_observer);
    let calibration = CalibrationStage::new(&calibration_feedback);

    let mut fuzzer = StdFuzzer::new(
        scheduler,
        feedback,
        objective
    );

    let mut harness = |_emu: &mut Emulator<_, _, _, _, _, _, _>, input: &BytesInput| {
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
        }
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

    // Run the initial inputs in the fuzzer
    for input in initial_inputs {
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, &input)
            .unwrap();
    }

    let mut stages = tuple_list!(calibration, tracing, json_mut, random_ascii_mut);
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager).expect("error in the fuzzing loop");
    Ok(())
}
