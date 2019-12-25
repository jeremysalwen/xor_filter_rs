// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]
#[macro_use] extern crate libfuzzer_sys;
#[macro_use] extern crate log;
extern crate xor_filter;
extern crate arbitrary;

use std::collections::HashSet;
use arbitrary::*;

fn fuzztest(data: &[u8]) -> Result<(), <FiniteBuffer<'_> as Unstructured>::Error> {
    let _ = env_logger::try_init();
    let mut buff = FiniteBuffer::new(data, 4048).unwrap();
    let positives :Vec<i64> = Arbitrary::arbitrary(&mut buff)?;
    let mut negatives :HashSet<i64> = Arbitrary::arbitrary(&mut buff)?;
    for positive in &positives {
        negatives.remove(positive);
    }
    let negative_vec = negatives.iter().copied().collect();
    debug!("i64 FUZZ TEST positives {:?}",positives);
    debug!("i64 FUZZ TEST negatives {:?}",negative_vec);
    xor_filter::test_util::test_construction(&positives, &negative_vec);
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    fuzztest(data).ok();
});
