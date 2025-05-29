use std::{borrow::Cow, num::{NonZeroUsize}};
use jvob::{JValueMap, json_values_byte_offsets};

use libafl::{inputs::{HasMutatorBytes, ResizableMutator}, mutators::{MutationResult, Mutator}, state::{HasMaxSize, HasRand}, HasMetadata};
use libafl::{
    Error
};
use libafl_bolts::{rands::Rand, Named};
pub struct RandomAsciiCharsMutator;
const ALLOWED_CHARS: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[{]};:,<.>/?<";

impl RandomAsciiCharsMutator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Named for RandomAsciiCharsMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("RandomAsciiCharsMutator");
        &NAME
    }
}

impl<I, S> Mutator<I, S> for RandomAsciiCharsMutator where
S: HasMetadata + HasRand + HasMaxSize,
I: ResizableMutator<u8> + HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<libafl::mutators::MutationResult, Error> {
        let input_bytes = input.mutator_bytes();
        let _spans: Vec<JValueMap> = match json_values_byte_offsets(input_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                // println!("skipped 4!");
                // vec![JValueMap::new((0, size.into()), String::new(), jvob::JType::JString)]
                return Ok(MutationResult::Skipped);
            }
        };
        let span_idx = state.rand_mut().below(NonZeroUsize::new(_spans.len()).unwrap());
        let off = state.rand_mut().between(_spans[span_idx].region().0, _spans[span_idx].region().1);    // below(size);

        let len = _spans[span_idx].region().1;
        let bytes = input.mutator_bytes_mut();

        for byte in bytes.iter_mut().skip(off).take(len) {
            *byte = ALLOWED_CHARS.as_bytes()[
                state.rand_mut().below(NonZeroUsize::new(ALLOWED_CHARS.len()).unwrap())
            ]
        }
        
        Ok(MutationResult::Mutated)
   }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<libafl::corpus::CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
