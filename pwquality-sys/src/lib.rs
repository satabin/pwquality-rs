// Copyright (c) 2017, Lucas Satabin
// Licensed under the MIT license, see the LICENSE file or <http://opensource.org/licenses/MIT>
extern crate libc;

use libc::{c_char, c_void, c_int};

pub static PWQ_SETTING_DIFF_OK: c_int = 1;
pub static PWQ_SETTING_MIN_LENGTH: c_int = 3;
pub static PWQ_SETTING_DIG_CREDIT: c_int = 4;
pub static PWQ_SETTING_UP_CREDIT: c_int = 5;
pub static PWQ_SETTING_LOW_CREDIT: c_int = 6;
pub static PWQ_SETTING_OTH_CREDIT: c_int = 7;
pub static PWQ_SETTING_MIN_CLASS: c_int = 8;
pub static PWQ_SETTING_MAX_REPEAT: c_int = 9;
pub static PWQ_SETTING_DICT_PATH: c_int = 10;
pub static PWQ_SETTING_MAX_CLASS_REPEAT: c_int = 11;
pub static PWQ_SETTING_GECOS_CHECK: c_int = 12;
pub static PWQ_SETTING_BAD_WORDS: c_int = 13;
pub static PWQ_SETTING_MAX_SEQUENCE: c_int = 14;
pub static PWQ_SETTING_DICT_CHECK: c_int = 15;
pub static PWQ_SETTING_USER_CHECK: c_int = 16;
pub static PWQ_SETTING_ENFORCING: c_int = 17;

/// An error returned by the underlying library.
/// The `UnknownError` should never be returned unless a new error
/// code is added in `pwquality`.
#[derive(Clone, Debug)]
pub enum Error {
    FatalFailure, // = -1;
    Integer, // = -2;
    CfgfileOpen, // = -3;
    CfgfileMalformed, // = -4;
    UnknownSetting, // = -5;
    NonIntSetting, // = -6;
    NonStrSetting, // = -7;
    MemAlloc, // = -8;
    TooSimilar, // = -9;
    MinDigits, // = -10;
    MinUppers, // = -11;
    MinLowers, // = -12;
    MinOthers, // = -13;
    MinLength, // = -14;
    Palindrome, // = -15;
    CaseChangesOnly, // = -16;
    Rotated, // = -17;
    MinClasses, // = -18;
    MaxConsecutive, // = -19;
    EmptyPassword, // = -20;
    SamePassword, // = -21;
    CracklibCheck, // = -22;
    Rng, // = -23;
    GenerationFailed, // = -24;
    UserCheck, // = -25;
    GecosCheck, // = -26;
    MaxClassRepeat, // = -27;
    BadWords, // = -28;
    MaxSequence, // = -29;

    UnknownError(i32),
}

impl Error {

    pub fn from_int(i: c_int) -> Self {
        match i {
            -1 => Error::FatalFailure,
            -2 => Error::Integer,
            -3 => Error::CfgfileOpen,
            -4 => Error::CfgfileMalformed,
            -5 => Error::UnknownSetting,
            -6 => Error::NonIntSetting,
            -7 => Error::NonStrSetting,
            -8 => Error::MemAlloc,
            -9 => Error::TooSimilar,
            -10 => Error::MinDigits,
            -11 => Error::MinUppers,
            -12 => Error::MinLowers,
            -13 => Error::MinOthers,
            -14 => Error::MinLength,
            -15 => Error::Palindrome,
            -16 => Error::CaseChangesOnly,
            -17 => Error::Rotated,
            -18 => Error::MinClasses,
            -19 => Error::MaxConsecutive,
            -20 => Error::EmptyPassword,
            -21 => Error::SamePassword,
            -22 => Error::CracklibCheck,
            -23 => Error::Rng,
            -24 => Error::GenerationFailed,
            -25 => Error::UserCheck,
            -26 => Error::GecosCheck,
            -27 => Error::MaxClassRepeat,
            -28 => Error::BadWords,
            -29 => Error::MaxSequence,
            _ => Error::UnknownError(i)
        }
    }

}

pub enum OpaqueSettings{}

extern {
    pub fn pwquality_default_settings() -> *const OpaqueSettings;
    pub fn pwquality_free_settings(pwq: *const OpaqueSettings);
    pub fn pwquality_read_config(pwq: *const OpaqueSettings, cfgfile: *const c_char, auxerror: *mut *mut c_void) -> c_int;
    pub fn pwquality_set_int_value(pwq: *const OpaqueSettings, setting: c_int, value: c_int) -> c_int;
    pub fn pwquality_set_str_value(pwq: *const OpaqueSettings, setting: c_int, value: *const c_char) -> c_int;
    pub fn pwquality_get_int_value(pwq: *const OpaqueSettings, setting: c_int, value: *mut c_int) -> c_int;
    pub fn pwquality_get_str_value(pwq: *const OpaqueSettings, setting: c_int, value: *mut *mut c_char) -> c_int;

    pub fn pwquality_generate(pwq: *const OpaqueSettings, entropy_bits: c_int, password: *mut *mut c_char) -> c_int;
    pub fn pwquality_check(pwq: *const OpaqueSettings, password: *const c_char, oldpassword: *const c_char, user: *const c_char, auxerror: *mut *mut c_void) -> c_int;

}
