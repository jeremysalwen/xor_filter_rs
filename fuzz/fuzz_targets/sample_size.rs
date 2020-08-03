#![no_main]
#![feature(clamp)]

extern crate libfuzzer_sys;
extern crate arbitrary;
extern crate xor_filter;
use libfuzzer_sys::fuzz_target;
use arbitrary::*;
use xor_filter::tests::statistical::normal_approx_sample_size;



fn check_sample_size(data:&[u8]) -> Result<(), <FiniteBuffer<'_> as Unstructured>::Error> {
    let mut buff = FiniteBuffer::new(data, 4048).unwrap();
    let p0 = f64::arbitrary(&mut buff)?.clamp(0.0,1.0);
    let p1 = f64::arbitrary(&mut buff)?.clamp(0.0,1.0);
    let false_positive_rate=f64::arbitrary(&mut buff)?.clamp(0.0,1.0);
    let false_negative_rate=f64::arbitrary(&mut buff)?.clamp(0.0,1.0);
    let (n,k) = normal_approx_sample_size(p0,p1,false_positive_rate, false_negative_rate);
    return Ok(())
}

fuzz_target!(|data: &[u8]| {
    check_sample_size(&data).ok();
});
