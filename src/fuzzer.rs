use core::time::Duration;
use std::{borrow::Cow, env, fmt, fs, io::Read,  num::{NonZero, NonZeroUsize}, path::PathBuf, ptr::NonNull};
use clap::{Parser};
// use std::{env, fmt::Write, fs::DirEntry, io, path::PathBuf, process};
use env_logger::Builder;

// use core::time::Duration;
// use std::{env, path::PathBuf, process};

use libafl::{corpus::{InMemoryOnDiskCorpus, OnDiskCorpus}, feedbacks::MaxMapFeedback, inputs::{HasMutatorBytes, ResizableMutator}, mutators::{MutationResult, Mutator}, observers::{CanTrack, CmpValues, CmpValuesMetadata}, Evaluator, Fuzzer};
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
        StdMutationalStage,
    },
    feedback_or,
    Error, HasMetadata,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, tokens_mutations, scheduled::HavocScheduledMutator, token_mutations::I2SRandReplace},
    executors::{ExitKind, ShadowExecutor},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    // schedulers::QueueScheduler,
    state::{StdState, HasMaxSize, HasRand},
};
use json_syntax::{CodeMap, Object, Parse, Value};
use serde::{Deserialize, Serialize};
use serde_json::{Result as SerdeResult};
use libafl_bolts::{rands::Rand, AsSliceMut, HasLen, Named};
// #[allow(unused_imports)]
use libafl_bolts::{
    shmem::{ShMemProvider, StdShMemProvider},
    rands::StdRand,
    tuples::{tuple_list, Merge},
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

fn extract_value_spans(json: &[u8]) -> Vec<(usize, usize)> {
    // let parsed = Value::parse_str(String::from_utf8(json.to_vec()).unwrap().as_str()).unwrap();
    // println!("parsed: {:?}", parsed);
    let mut spans: Vec<(usize, usize)> = Vec::new(); 
    let mut tmp_span: (usize, usize) = (0,0);
    let mut is_open = false;
    let mut colon_found = false;
    for (pos, b) in json.to_vec().into_iter().enumerate() {
        if b as char == ':' {
            colon_found = true;
        }
        if colon_found {
            if b as char == '\"' {
                if is_open {
                    tmp_span.1 = pos;
                    spans.push(tmp_span);
                    is_open = false;
                    colon_found = false;
                } else {
                    tmp_span.0 = pos;
                    is_open = true;
                }
            }
        }
    }
    spans

    // fn walk(node: &(Value, CodeMap), spans: &mut Vec<(usize, usize)> ) {
    //         for _f in node.0.as_object().unwrap().entries() {
    //             println!("&_f.value: {:?}", &_f.value.as_str());

                // match &_f.value {
                //     Value::Object(o)=> {
                //         // for _f in o.entries() {
                //         // _f.into_mapped(key_offset, value_offset)
                //             walk(&(_f.value, node.1), spans);
                //         // }
                //     },
                //     Value::Array(items) => {
                //         for item in items {
                //             match item {
                //                 Value::Boolean(_) | Value::Null | Value::String(_) | Value::Number(_) => {
                //                     let idx = match node.index_of(&_f.key) {
                //                         Some(_u) => _u,
                //                         None => 0
                //                     };
                //                     if idx != 0 {
                //                         spans.push((idx, idx + node.len()));
                //                     }
                //                 },
                //                 _ => {
                //                     walk(item.as_object().unwrap(), spans);
                //                 }
                //             }
                //         }
                //     },
                //     Value::Boolean(_) | Value::Null | Value::String(_) | Value::Number(_) => {
                //         let idx = match node.index_of(&_f.key) {
                //             Some(_u) => _u,
                //             None => 0
                //         };
                //         if idx != 0 {
                //             spans.push((idx, idx + node.len()));
                //         }
                //     }
                // }
            // }

    // }

    // let mut spans = vec![];
    // walk(parsed, &mut spans);
    // spans
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
        let _: TestInput = match serde_json::from_slice(&input_bytes) {
            Ok(_j) => _j,
            Err(_e) => {
                return Ok(MutationResult::Skipped);
            }
        };
        // extract_value_spans(input_bytes);
        println!("Before span finding");
        let _spans = extract_value_spans(&input_bytes);
        // for _s in _spans {
        //     println!("span: {:?}, {:?}", _s.0, _s.1);
        // }
        let Some(size) = NonZero::new(input_bytes.len()) else {
            return Ok(MutationResult::Skipped);
        };
        let Some(meta) = state.metadata_map().get::<CmpValuesMetadata>() else {
            return Ok(MutationResult::Skipped);
        };
        // let in_bytes = input.mutator_bytes();
        log::trace!("meta: {meta:x?}");


        // println!("input : {_json:?}");
        // _json.to_string();

        let Some(cmps_len) = NonZero::new(meta.list.len()) else {
            return Ok(MutationResult::Skipped);
        };


        // let idx = state.rand_mut().below(cmps_len);
        let idx = state.rand_mut().below(cmps_len);
        let span_idx = state.rand_mut().below(NonZeroUsize::new(_spans.clone().len()).unwrap());
        // Here we have to find a random offset choosing among the json value regions
        let off = state.rand_mut().between(_spans[span_idx].0, _spans[span_idx].1);    // below(size);
        // Here the length must be from upper region bound minus the lower region bound
        let len = input.mutator_bytes().len();
        let bytes = input.mutator_bytes_mut();

        let meta = state.metadata_map().get::<CmpValuesMetadata>().unwrap();
        let cmp_values = &meta.list[idx];

        // TODO: do not use from_ne_bytes, it's for host not for target!! we should use a from_target_ne_bytes....

        let mut result = MutationResult::Skipped;
        match cmp_values.clone() {
            CmpValues::U8(v) => {
                for byte in bytes.iter_mut().take(len).skip(off) {
                    if *byte == v.0 {
                        *byte = v.1;
                        result = MutationResult::Mutated;
                        break;
                    } else if *byte == v.1 {
                        *byte = v.0;
                        result = MutationResult::Mutated;
                        break;
                    }
                }
            }
            CmpValues::U16(v) => {
                let cmp_size = random_slice_size::<{ size_of::<u16>() }, S>(state);

                if len >= cmp_size {
                    for i in off..len - (cmp_size - 1) {
                        let mut val_bytes = [0; size_of::<u16>()];
                        val_bytes[..cmp_size].copy_from_slice(&bytes[i..i + cmp_size]);
                        let val = u16::from_ne_bytes(val_bytes);

                        if val == v.0 {
                            let new_bytes = &v.1.to_ne_bytes()[..cmp_size];
                            bytes[i..i + cmp_size].copy_from_slice(new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = &v.0.to_ne_bytes()[..cmp_size];
                            bytes[i..i + cmp_size].copy_from_slice(new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + cmp_size].copy_from_slice(&new_bytes[..cmp_size]);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + cmp_size].copy_from_slice(&new_bytes[..cmp_size]);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U32(v) => {
                let cmp_size = random_slice_size::<{ size_of::<u32>() }, S>(state);
                if len >= cmp_size {
                    for i in off..len - (cmp_size - 1) {
                        let mut val_bytes = [0; size_of::<u32>()];
                        val_bytes[..cmp_size].copy_from_slice(&bytes[i..i + cmp_size]);
                        let val = u32::from_ne_bytes(val_bytes);

                        if val == v.0 {
                            let new_bytes = &v.1.to_ne_bytes()[..cmp_size];
                            bytes[i..i + cmp_size].copy_from_slice(new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = &v.0.to_ne_bytes()[..cmp_size];
                            bytes[i..i + cmp_size].copy_from_slice(new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + cmp_size].copy_from_slice(&new_bytes[..cmp_size]);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + cmp_size].copy_from_slice(&new_bytes[..cmp_size]);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U64(v) => {
                let cmp_size = random_slice_size::<{ size_of::<u64>() }, S>(state);

                if len >= cmp_size {
                    for i in off..(len - (cmp_size - 1)) {
                        let mut val_bytes = [0; size_of::<u64>()];
                        val_bytes[..cmp_size].copy_from_slice(&bytes[i..i + cmp_size]);
                        let val = u64::from_ne_bytes(val_bytes);

                        if val == v.0 {
                            let new_bytes = &v.1.to_ne_bytes()[..cmp_size];
                            bytes[i..i + cmp_size].copy_from_slice(new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = &v.0.to_ne_bytes()[..cmp_size];
                            bytes[i..i + cmp_size].copy_from_slice(new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + cmp_size].copy_from_slice(&new_bytes[..cmp_size]);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + cmp_size].copy_from_slice(&new_bytes[..cmp_size]);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::Bytes(v) => {
                'outer: for i in off..len {
                    let mut size = core::cmp::min(v.0.len(), len - i);
                    while size != 0 {
                        if v.0.as_slice()[0..size] == input.mutator_bytes()[i..i + size] {
                            unsafe {
                                buffer_copy(input.mutator_bytes_mut(), v.1.as_slice(), 0, i, size);
                            }
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                    size = core::cmp::min(v.1.len(), len - i);
                    while size != 0 {
                        if v.1.as_slice()[0..size] == input.mutator_bytes()[i..i + size] {
                            unsafe {
                                buffer_copy(input.mutator_bytes_mut(), v.0.as_slice(), 0, i, size);
                            }
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                }
            }
        }

        Ok(result)
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

    cli_args.args.insert(0, program);
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

    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        RegionMutator::new()
    )));

    let mutator =
        HavocScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);
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

    let tracing = ShadowTracingStage::new();

    let mut stages = tuple_list!(
        CalibrationStage::new(&calibration_feedback), i2s, tracing, power);
    // let mut stages = tuple_list!(tracing);

    // log::info!("Processed {} inputs from disk.", files.len());
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager).expect("error in the fuzzing loop");
    Ok(())
}
