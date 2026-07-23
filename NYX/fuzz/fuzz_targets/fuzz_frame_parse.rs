#![no_main]

use libfuzzer_sys::fuzz_target;
use nyx_protocol::frame::Frame;

fuzz_target!(|data: &[u8]| {
    // We only care that parsing never panics or allocates unbounded memory.
    let _ = Frame::parse(data);
});
