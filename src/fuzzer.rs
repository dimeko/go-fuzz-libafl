use core::time::Duration;
use std::{borrow::Cow, env, fmt, fs, io::{BufReader, Read, Seek}, num::{NonZero, NonZeroUsize}, path::{Path, PathBuf}, ptr::NonNull};
use std::io::Cursor;
use clap::{Parser};
// use std::{env, fmt::Write, fs::DirEntry, io, path::PathBuf, process};
use env_logger::Builder;

// use core::time::Duration;
// use std::{env, path::PathBuf, process};

use libafl::{corpus::{CachedOnDiskCorpus, InMemoryOnDiskCorpus, OnDiskCorpus}, executors::{forkserver::ForkserverExecutorBuilder, ForkserverExecutor, HasObservers, StdChildArgs}, feedbacks::MaxMapFeedback, inputs::{HasMutatorBytes, ResizableMutator}, mutators::{MutationResult, Mutator}, observers::{CanTrack, CmpValues, CmpValuesMetadata, ObserversTuple, StdMapObserver}, stages::{colorization, mutational::MultiMutationalStage, FuzzTime, IfStage, PowerMutationalStage, StdMutationalStage, TimeTrackingStageWrapper}, state::HasCurrentTestcase, Evaluator, Fuzzer};
// use libafl::state::HasExecutions;
// #[allow(unused_imports)]
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
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
    },
    feedback_or,
    Error, HasMetadata,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, tokens_mutations, scheduled::HavocScheduledMutator, token_mutations::AflppRedQueen},
    executors::{ExitKind, ShadowExecutor},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    // schedulers::QueueScheduler,
    state::{StdState, HasMaxSize, HasRand},
};
use libafl_targets::{cmps::AflppCmpLogObserver, AflppCmpLogMap, AflppCmplogTracingStage};
use json_syntax::{CodeMap, Parse, Value};
use serde::{Deserialize, Serialize};
use libafl_bolts::{ownedref::OwnedRefMut, rands::Rand, shmem::{ShMem, UnixShMemProvider}, tuples::{Handled, RefIndexable}, AsSliceMut, Named, SerdeAny, StdTargetArgs};
// #[allow(unused_imports)]
use libafl_bolts::{
    shmem::{ShMemProvider, StdShMemProvider},
    rands::StdRand,
    tuples::{tuple_list, Merge},
    AsSlice,
};

use libafl_qemu::{elf::EasyElf, modules::{
        cmplog::{CmpLogChildModule, CmpLogObserver},
        edges::StdEdgeCoverageChildModule, EmulatorModuleTuple}, ArchExtras, Emulator, GuestAddr, MmapPerms, QemuExitError, QemuExitReason, QemuForkExecutor, QemuMappingsViewer, QemuShutdownCause, Regs
};

use libafl_targets::{CmpLogMap, EDGES_MAP_DEFAULT_SIZE};
pub type LibaflFuzzState =
    StdState<CachedOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;
#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct IsInitialCorpusEntryMetadata {}
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum JType {
    JString,
    JNumber,
    JBool,
    JNull
}

trait StringExt {
    fn trim_edges_bytes(&self) -> Option<String>;
}

impl StringExt for String {
    fn trim_edges_bytes(&self) -> Option<String> {
        let bytes = self.as_bytes();
        if bytes.len() <= 2 {
            return None;
        }

        // slice from second byte to byte before last
        std::str::from_utf8(&bytes[1..bytes.len() - 1])
            .ok()
            .map(|s| s.to_string())
    }
}

struct JValueMap {
    t: JType,
    region: (usize, usize),
    value: String
}

impl JValueMap {
    fn default() -> Self {
        return JValueMap {
            t: JType::JNull,
            region: (0, 0),
            value: String::new()
        }
    }

    fn new(_r: (usize, usize), _v: String, _t: JType) -> Self {
        return JValueMap { t: _t, region: _r, value: _v }
    }
}
// ------------------------------------------------------------------



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

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

fn random_slice_size<const SZ: usize, S>(state: &mut S) -> usize
where
    S: HasRand,
{
    let sz_log = SZ.ilog2() as usize;
    // # Safety
    // We add 1 so this can never be 0.
    // On 32 bit systems this could overflow in theory but this is highly unlikely.
    let sz_log_inclusive = unsafe { NonZero::new(sz_log + 1).unwrap_unchecked() };
    let res = state.rand_mut().below(sz_log_inclusive);
    2_usize.pow(res as u32)
}

#[derive(Debug, Default)]
struct RegionMutator;

impl RegionMutator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Named for RegionMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("RegionMutator");
        &NAME
    }
}

#[inline]
pub(crate) unsafe fn buffer_copy<T>(dst: &mut [T], src: &[T], from: usize, to: usize, len: usize) {
    debug_assert!(!dst.is_empty());
    debug_assert!(!src.is_empty());
    debug_assert!(from + len <= src.len());
    debug_assert!(to + len <= dst.len());
    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();
    if len != 0 {
        unsafe {
            core::ptr::copy(src_ptr.add(from), dst_ptr.add(to), len);
        }
    }
}
const SHMEM_ENV_VAR: &str = "__AFL_SHM_ID";
fn extract_value_spans(json: &[u8]) -> Option<Vec<JValueMap>> {
    let cursor = Cursor::new(json);
    let mut reader = BufReader::new(cursor);
    // let mut reader = BufReader::new(json);
    // let json_string = "{\"field_1\":\"stirng\",\"field_2\":{\"nest_1\":\"nest\",\"nest_2\":\"nesdfsdt\"},\"field_3\":[\"lsfas1\",\"lsda2\",\"l3asda\",\"l4sda\"]}";
    let mut _json_bytes_vec = Vec::new();
    let skip_code_map = ['{', '}', '[', ']', ':'];
    let mut json_values : Vec<JValueMap> = Vec::new();
    reader.read_to_end(&mut _json_bytes_vec).unwrap();
    let _: Result<(Value, CodeMap), json_syntax::parse::Error> = match Value::parse_str(String::from_utf8(_json_bytes_vec.clone()).unwrap().as_str()) {
        Ok(_p) => {
            'outer: for _map in _p.1 {
                reader.seek(std::io::SeekFrom::Start(0)).unwrap();

                // println!("Next Span: {:?} - {:?}", _map.1.span.start() ,  _map.1.span.end());
                let mut _rev: i64 = (_map.1.span.end() - _map.1.span.start() ) as i64;
                let mut tmp_value = String::new();
                for (pos, mut _jb) in reader.by_ref().bytes().enumerate().skip(_map.1.span.start()).take(_map.1.span.end() - _map.1.span.start() ) {
                    if _json_bytes_vec.len() <= ((pos as i64) + _rev) as usize { _rev = _rev - 2; continue;}
                    if skip_code_map.contains(&(_json_bytes_vec[((pos as i64) + _rev) as usize] as char)) {
                        _rev = _rev - 2;
                        continue 'outer;
                    }
                    tmp_value.push(_json_bytes_vec[pos] as char);
                    // tmp_value.push();
                    _rev = _rev - 2;
                }
                let _type: JType;
                match tmp_value.chars().nth(0).unwrap() {
                    '\"' => {
                        json_values.push(JValueMap::new((_map.1.span.start()+1, _map.1.span.end()-1), tmp_value, JType::JString));
                    },
                    't' | 'f' => {
                        json_values.push(JValueMap::new((_map.1.span.start(), _map.1.span.end()), tmp_value, JType::JBool));
                    },
                    'n' => {
                        json_values.push(JValueMap::new((_map.1.span.start(), _map.1.span.end()), tmp_value, JType::JNull));
                    },
                    c => {
                        if c.is_ascii_digit() {
                            json_values.push(JValueMap::new((_map.1.span.start(), _map.1.span.end()), tmp_value, JType::JNumber));
                        }
                    }                    
                }
            }

            // for _s in json_values {
            //     if _s.t == JType::JString {
            //         println!("found: {:?}", _s.value.trim_edges_bytes().unwrap());
            //     } else {
            //         println!("found: {:?}", _s.value);
            //     }
            //     println!("checking with original json: ");
            //     for _i in _s.region.0.._s.region.1 {
            //         print!("{:?}", _json_bytes_vec[_i] as char);
            //     }
            //     println!();
            // }

            return Some(json_values);
        },
        Err(_r) => {
            // println!("not a valid json");
            return None;
        }
    };
}

#[derive(Debug, Serialize, Deserialize)]
struct Nested {
    nest_1: String,
    nest_2: String
}
#[derive(Debug, Serialize, Deserialize)]
struct TestInput {
    field_1: String,
    field_2: Nested,
    field_3: Vec<String>
}

impl fmt::Display for TestInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _s = serde_json::to_string(self).unwrap();
        write!(f, "{}", _s)
    }
}

impl<I, S> Mutator<I, S> for RegionMutator where
S: HasMetadata + HasRand + HasMaxSize,
I: ResizableMutator<u8> + HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<libafl::mutators::MutationResult, Error> {
        let input_bytes = input.mutator_bytes();
        let Some(size) = NonZero::new(input_bytes.len()) else {
            // println!("skipped 1");

            return Ok(MutationResult::Skipped);
        };

        let _spans: Vec<JValueMap> = match extract_value_spans(&input_bytes) {
            Some(s) => s,
            None => {
                // println!("skipped 4!");
                return Ok(MutationResult::Skipped);
            }
        };

        // let idx = state.rand_mut().below(cmps_len);
        // let idx = state.rand_mut().below(cmps_len);
        let span_idx = state.rand_mut().below(NonZeroUsize::new(_spans.len()).unwrap());
        // Here we have to find a random offset choosing among the json value regions
        let off = state.rand_mut().between(_spans[span_idx].region.0, _spans[span_idx].region.1);    // below(size);
        // Here the length must be from upper region bound minus the lower region bound
        let len = _spans[span_idx].region.1 - off;//input.mutator_bytes().len();
        let bytes = input.mutator_bytes_mut();

        // let meta = state.metadata_map().get::<CmpValuesMetadata>().unwrap();
        // let cmp_values = &meta.list[idx];

        // TODO: do not use from_ne_bytes, it's for host not for target!! we should use a from_target_ne_bytes....
        // println!("value: {:?}", _spans[span_idx].value);
        // print!("off {:?}, len: {:?}, bytes_len: {:?}\n", off, len, bytes.len()); 

        for byte in bytes.iter_mut().skip(off).take(len) {
            // print!("from {:?}", *byte as char); 
            *byte = state.rand_mut().below(NonZeroUsize::new(127).unwrap()) as u8;
            // print!(" to {:?}\n", *byte as char); 
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<libafl::corpus::CorpusId>) -> Result<(), Error> {
            Ok(())
    }
}

pub fn fuzz() -> Result<(), Error> {
    #![allow(unused_mut)]
    #![allow(unused_variables)]
    #![allow(unreachable_code)]
    let mut builder = Builder::from_default_env();

    let mut log_level: log::LevelFilter = log::LevelFilter::Warn;
    let mut cli_args = FuzzerArgs::parse();

    if cli_args.verbose {
        log_level = log::LevelFilter::Debug;
    }
    builder
        .filter(None, log_level)
        .init();

    // let corpus_files = cli_args
    //     .input_dir
    //     .read_dir()
    //     .expect("Failed to read corpus dir")
    //     .collect::<Result<Vec<fs::DirEntry>, io::Error>>()
    //     .expect("Failed to read dir entry");
    // let in_dir = [PathBuf::from(cli_args.input_dir)];
    let mut initial_inputs = vec![];

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
            let input = BytesInput::new(buffer);
            initial_inputs.push(input);
        }
    }


    let program = env::args().next().unwrap();
    log::info!("Program: {program:}");

    cli_args.args.insert(0, program.clone());
    log::info!("ARGS: {:#?}", cli_args.args);

    let mut shmem_provider = StdShMemProvider::new().unwrap();

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
    let emulator_modules = tuple_list!(
        StdEdgeCoverageChildModule::builder()
            .const_map_observer(edges_observer.as_mut())
            .build()?,
        CmpLogChildModule::default(),
    );

    let emulator = Emulator::empty()
        .qemu_parameters(cli_args.args)
        .modules(emulator_modules)
        .build()
        .expect("QEMU init failed");

    let qemu = emulator.qemu();
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::info!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    qemu.entry_break(test_one_input_ptr); // LLVMFuzzerTestOneInput
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

    // let files = corpus_files
    //     .iter()
    //     .map(|x| x.path())
    //     .collect::<Vec<PathBuf>>();

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
    );

    let mut cmplog_shmem = shmem_provider.uninit_on_shmem::<AflppCmpLogMap>().unwrap();

    // Let the Forkserver know the CmpLog shared memory map ID.
    // unsafe {
    //     cmplog_shmem.write_to_env(SHM_CMPLOG_ENV_VAR).unwrap();
    // }
    let cmpmap = unsafe { OwnedRefMut::from_shmem(&mut cmplog_shmem) };
    let cpm_log_obs = AflppCmpLogObserver::new("red_queen_observer", cmpmap, true);   
    let cmplog_ref = cpm_log_obs.handle();

    // let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
    //     RegionMutator::new()
    // )));


    let red_queen = MultiMutationalStage::<_, _, BytesInput, _, _, _>::new(
        AflppRedQueen::with_cmplog_options(true, true),
    );

    // let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));
    let mutator =
        HavocScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);
    let inner_mutational_stage = StdMutationalStage::new(mutator);
    let mutational_stage = TimeTrackingStageWrapper::<FuzzTime, _, _>::new(inner_mutational_stage);

    let calibration_feedback = MaxMapFeedback::new(&edges_observer);

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

    let mut executor = QemuForkExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer.clone()),
        &mut fuzzer,
        &mut state,
        &mut manager,
        shmem_provider.clone(),
        Duration::from_millis(5000))
    .expect("Failed to create QemuExecutor");

    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // if state.must_load_initial_inputs() {
    //     state
    //         .load(&mut fuzzer, &mut executor, &mut manager, &in_dir.clone())
    //         .unwrap_or_else(|err| {
    //             log::info!("Failed to load initial corpus: error: {:?}", err);
    //             process::exit(0);
    //         });
    //     log::info!("We imported {} inputs from disk.", state.corpus().count());
    // }
    for input in initial_inputs {
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, &input)
            .unwrap();
    }
    let mut shmem = shmem_provider
        .new_shmem(65336)
        .unwrap();
    unsafe {
        shmem.write_to_env(SHMEM_ENV_VAR).unwrap();
    }
    let shmem_buf = shmem.as_slice_mut();
    let fork_executor = ForkserverExecutor::builder()
        .program(&program)
        .coverage_map_size(65336)
        .build_dynamic_map(HitcountsMapObserver::new(unsafe {StdMapObserver::new("std_observer", shmem.as_slice_mut())}), tuple_list!(time_observer.clone())).unwrap();

    let tracing = AflppCmplogTracingStage::new(fork_executor, cmplog_ref);

    // let tracing = AflppCmplogTracingStage::new(&executor, cmplog_ref);

    // let tracing = ShadowTracingStage::new();
    // let mutation = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    // let inner_mutational_stage = SupportedMutationalSt::PowerMutational(
    //         StdPowerMutationalStage::<_, _, BytesInput, _, _, _>::new(mutation),
    //         PhantomData);
    // let mutational_stage = TimeTrackingStageWrapper::<FuzzTime, _, _>::new(inner_mutational_stage);

    // let mut stages = tuple_list!(
    //     CalibrationStage::new(&calibration_feedback), tracing, i2s, power);

    let mut stages = tuple_list!(
        CalibrationStage::new(&calibration_feedback), mutational_stage, red_queen, tracing);

        // log::info!("Processed {} inputs from disk.", files.len());
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager).expect("error in the fuzzing loop");
    Ok(())
}
