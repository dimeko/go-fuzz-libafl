use std::{borrow::Cow, num::{NonZero, NonZeroUsize}};

use libafl::{
    inputs::{HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator},
    observers::{CmpValues, CmpValuesMetadata}};

use libafl::{
    Error, HasMetadata,
    state::{ HasMaxSize, HasRand},
};

use jvob::{JValueMap, json_values_byte_offsets};
use libafl_bolts::{rands::Rand, HasLen, Named, AsSlice};

#[derive(Debug, Default)]
pub struct JsonMutator;

impl JsonMutator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Named for JsonMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("JsonMutator");
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

impl<I, S> Mutator<I, S> for JsonMutator where
S: HasMetadata + HasRand + HasMaxSize,
I: ResizableMutator<u8> + HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<libafl::mutators::MutationResult, Error> {
        let input_bytes = input.mutator_bytes();
        let _spans: Vec<JValueMap> = match json_values_byte_offsets(input_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                return Ok(MutationResult::Skipped);
            }
        };
        let Some(meta) = state.metadata_map().get::<CmpValuesMetadata>() else {
            // println!("meta skipped: {:?}", meta);

            return Ok(MutationResult::Skipped);
        };
        // println!("meta continue: {:?}", meta);

        let Some(cmps_len) = NonZero::new(meta.list.len()) else {
            return Ok(MutationResult::Skipped);
        };

        let idx = state.rand_mut().below(cmps_len);
        let span_idx = state.rand_mut().below(
            NonZeroUsize::new(_spans.len()).unwrap());

        let off = state.rand_mut().between(
            _spans[span_idx].region().0, _spans[span_idx].region().1);    // below(size);

        let len = _spans[span_idx].region().1;
        let bytes = input.mutator_bytes_mut();

        let meta = match state.metadata_map().get::<CmpValuesMetadata>() {
            Some(m) => {
                m
            },
            None => {
                println!("could not get CmpValuesMetadata");
                return Ok(MutationResult::Skipped);
            }
        };

        let cmp_values = &meta.list[idx];
        let mut result = MutationResult::Skipped;

        match cmp_values {
            CmpValues::U8((v1, v2, v1_is_const)) => {
                for byte in bytes.iter_mut().take(len).skip(off) {
                    if !v1_is_const && *byte == *v1 {
                        *byte = *v2;
                        result = MutationResult::Mutated;
                        break;
                    } else if *byte == *v2 {
                        *byte = *v1;
                        result = MutationResult::Mutated;
                        break;
                    }
                    // here, we need an else to skip the mutation imidiatelly and only
                    // if it is skipped move to the next mutation and resize the input
                }
            }
            CmpValues::U16((v1, v2, v1_is_const)) => {
                if len >= size_of::<u16>() {
                    for i in off..=len - size_of::<u16>() {
                        let val =
                            u16::from_ne_bytes(bytes[i..i + size_of::<u16>()].try_into().unwrap());
                        if !v1_is_const && val == *v1 {
                            let new_bytes = v2.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if !v1_is_const && val.swap_bytes() == *v1 {
                            let new_bytes = v2.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == *v2 {
                            let new_bytes = v1.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == *v2 {
                            let new_bytes = v1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U32((v1, v2, v1_is_const)) => {
                if len >= size_of::<u32>() {
                    for i in off..=len - size_of::<u32>() {
                        let val =
                            u32::from_ne_bytes(bytes[i..i + size_of::<u32>()].try_into().unwrap());
                        if !v1_is_const && val == *v1 {
                            let new_bytes = v2.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if !v1_is_const && val.swap_bytes() == *v1 {
                            let new_bytes = v2.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == *v2 {
                            let new_bytes = v1.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == *v2 {
                            let new_bytes = v1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U64((v1, v2, v1_is_const)) => {
                if len >= size_of::<u64>() {
                    for i in off..=len - size_of::<u64>() {
                        let val =
                            u64::from_ne_bytes(bytes[i..i + size_of::<u64>()].try_into().unwrap());
                        if !v1_is_const && val == *v1 {
                            let new_bytes = v2.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if !v1_is_const && val.swap_bytes() == *v1 {
                            let new_bytes = v2.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == *v2 {
                            let new_bytes = v1.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == *v2 {
                            let new_bytes = v1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
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
                                buffer_copy(
                                    input.mutator_bytes_mut(),
                                    v.1.as_slice(), 0, i, size);
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
                                buffer_copy(
                                    input.mutator_bytes_mut(),
                                    v.0.as_slice(), 0, i, size);
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
