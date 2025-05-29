use std::{borrow::Cow, num::{NonZeroUsize}};
use jvob::{JValueMap, json_values_byte_offsets};

use libafl::{inputs::{HasMutatorBytes, ResizableMutator}, mutators::{MutationResult, Mutator}, state::{HasMaxSize, HasRand}, HasMetadata};
use libafl::{
    Error
};
use libafl_bolts::{rands::Rand, Named};
pub struct RandomResizeMutator;

const ALLOWED_CHARS: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]};:,<.>/?<";

// impl RandomResizeMutator {
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

impl Named for RandomResizeMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("RandomResizeMutator");
        &NAME
    }
}

impl<I, S> Mutator<I, S> for RandomResizeMutator where
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

        let new_bytes: Vec<u8> = {
            let num_of_bytes = state.rand_mut().below(
                NonZeroUsize::new(30).unwrap());

            let mut random_bytes = Vec::<u8>::new();
            for _ in 0..num_of_bytes {
                random_bytes.push(
                    ALLOWED_CHARS.as_bytes()[
                        state.rand_mut().below(NonZeroUsize::new(
                            ALLOWED_CHARS.len()).unwrap())
                    ]
                );
            }
            random_bytes
        };
        let span_to_resize = state.rand_mut().below(
            NonZeroUsize::new(_spans.len()).unwrap());
        let _start_off = state.rand_mut().between(
                _spans[span_to_resize].region().0,
                _spans[span_to_resize].region().1-1);
        input.splice(_start_off.._start_off, new_bytes.iter().copied());
        
        Ok(MutationResult::Mutated)
   }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<libafl::corpus::CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
