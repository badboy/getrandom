// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::Error;
use core::{convert::TryInto, ffi::c_void, mem::MaybeUninit, num::NonZeroU32, ptr};
use once_cell::sync::OnceCell;

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

/// The kinds of RNG that may be available
#[derive(Clone, Copy, Debug, PartialEq)]
enum Rng {
    Preferred,
    Fallback,
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        hAlgorithm: *mut c_void,
        pBuffer: *mut u8,
        cbBuffer: u32,
        dwFlags: u32,
    ) -> u32;
}

#[cfg(not(target_vendor = "uwp"))]
#[link(name = "advapi32")]
extern "system" {
    // Forbidden when targeting UWP
    #[link_name = "SystemFunction036"]
    pub fn RtlGenRandom(RandomBuffer: *mut u8, RandomBufferLength: u32) -> u8;
}

// BCryptGenRandom was introduced in Windows Vista. However, CNG Algorithm
// Pseudo-handles (specifically BCRYPT_RNG_ALG_HANDLE) weren't introduced
// until Windows 10, so we cannot use them yet. Note that on older systems
// these Pseudo-handles are interpreted as pointers, causing crashes if used.
fn bcrypt_random(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    // Will always succeed given the chunking in getrandom_inner().
    let len: u32 = dest.len().try_into().unwrap();
    // SAFETY: dest is valid, writable buffer of length len
    let ret = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            dest.as_mut_ptr() as *mut u8,
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    // NTSTATUS codes use the two highest bits for severity status.
    if ret >> 30 != 0b11 {
        return Ok(());
    }
    // We zeroize the highest bit, so the error code will reside
    // inside the range designated for OS codes.
    let code = ret ^ (1 << 31);
    // SAFETY: the second highest bit is always equal to one,
    // so it's impossible to get zero. Unfortunately the type
    // system does not have a way to express this yet.
    let code = unsafe { NonZeroU32::new_unchecked(code) };
    Err(Error::from(code))
}

/// Generate random numbers using the fallback RNG function (RtlGenRandom)
#[cfg(not(target_vendor = "uwp"))]
fn fallback_rng(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    let ret = unsafe { RtlGenRandom(dest.as_mut_ptr() as *mut u8, dest.len() as u32) };
    if ret == 0 {
        return Err(Error::WINDOWS_RTL_GEN_RANDOM);
    }
    Ok(())
}

/// We can't use RtlGenRandom with UWP, so there is no fallback
#[cfg(target_vendor = "uwp")]
fn fallback_rng(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}

pub fn getrandom_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    let rng_fn = get_rng();

    // Prevent overflow of u32
    for chunk in dest.chunks_mut(u32::max_value() as usize) {
        rng_fn(chunk)?;
    }
    Ok(())
}

/// Returns the RNG that should be used
///
/// Panics if they are both broken
fn get_rng() -> fn(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    // Assume that if the preferred RNG is broken the first time we use it, it likely means
    // that: the DLL has failed to load, there is no point to calling it over-and-over again,
    // and we should cache the result
    static VALUE: OnceCell<Rng> = OnceCell::new();
    match VALUE.get_or_init(choose_rng) {
        Rng::Preferred => bcrypt_random,
        Rng::Fallback => fallback_rng,
    }
}

/// Test whether we should use the preferred or fallback RNG
///
/// If the preferred RNG is successful, we choose it. Otherwise, if the fallback RNG is successful,
/// we choose that
///
/// Panics if both the preferred and the fallback RNG are both non-functional
fn choose_rng() -> Rng {
    let mut dest = [MaybeUninit::uninit(); 1];

    let preferred_error = match bcrypt_random(&mut dest) {
        Ok(_) => return Rng::Preferred,
        Err(e) => e,
    };

    match fallback_rng(&mut dest) {
        Ok(_) => return Rng::Fallback,
        Err(fallback_error) => panic!(
            "preferred RNG broken: `{}`, fallback RNG broken: `{}`",
            preferred_error, fallback_error
        ),
    }
}
