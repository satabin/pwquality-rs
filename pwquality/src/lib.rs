// Copyright (c) 2017, Lucas Satabin
// Licensed under the MIT license, see the LICENSE file or <http://opensource.org/licenses/MIT>
extern crate pwquality_sys;
extern crate libc;

use pwquality_sys::*;

use libc::c_char;

use std::ffi::{CStr, CString};
use std::ptr::{null, null_mut};

use std::path::Path;

/// Representation of an instance of `pwquality`.
/// Each instance has its own settings, that can be
/// changed.
#[derive(Debug)]
pub struct PWQuality {
    pwq: *const OpaqueSettings
}

impl PWQuality {

    /// Creates a new isntance with default settings.
    pub fn new() -> Self {
        let pwq = unsafe {
            pwquality_default_settings()
        };
        PWQuality {
            pwq
        }
    }

    /// Creates a new instance with default configuration.
    #[inline]
    pub fn from_default_config() -> Result<Self, Error> {
        PWQuality::from_optional_config(None::<&str>)
    }

    /// Creates a new instance with given configuration file.
    #[inline]
    pub fn from_config<P: AsRef<Path>>(config_path: P) -> Result<Self, Error> {
        PWQuality::from_optional_config(Some(config_path))
    }

    /// Creates a new instance with given configuration file.
    /// If `None` is passed, then default configuration is used.
    pub fn from_optional_config<P: AsRef<Path>>(config_path: Option<P>) -> Result<Self, Error> {
        let c_path = match config_path {
            Some(config_path) => CString::new(config_path.as_ref().to_str().unwrap()).unwrap().as_ptr(),
            None => null()
        };

        let (res, pwq) = unsafe {
            let pwq = pwquality_default_settings();
            let res = pwquality_read_config(pwq, c_path, null_mut());
            (res, pwq)
        };
        if res < 0 {
            Err(Error::from_int(res))
        } else {
            Ok(PWQuality {
                pwq
            })
        }
    }

    /// Sets the minimum number of changes required between old and new password.
    /// A value of `None` disables the check.
    pub fn set_min_diff(&self, min: Option<i32>) {
        let val = min.unwrap_or_else(|| { 0 });
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_DIFF_OK, val);
            assert!(res == 0);
        }
    }

    /// Returns the minimum number of changes required between old and new password.
    /// Returns `None` if check is disabled.
    pub fn get_min_diff(&self) -> Option<i32> {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_DIFF_OK, result);
            assert!(res == 0);
            if *result == 0 {
                None
            } else {
                Some(*result)
            }
        }
    }

    /// Sets the minimum accepted length for a password.
    /// Any number less than `6` will be replaced by `6`.
    pub fn set_min_length(&self, min: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_MIN_LENGTH, min);
            assert!(res == 0);
        }
    }

    /// Returns the minimum accepted length for a password.
    pub fn get_min_length(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_MIN_LENGTH, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the digit credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having digits in a password;
    ///  - if `credit < 0`, it represents the minimum number of digits required in a password.
    pub fn set_digit_credit(&self, credit: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_DIG_CREDIT, credit);
            assert!(res == 0);
        }
    }

    /// Returns the digit credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having digits in a password;
    ///  - if `credit < 0`, it represents the minimum number of digits required in a password.
    pub fn get_digit_credit(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_DIG_CREDIT, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the uppercase letter credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having uppercase letters in a password;
    ///  - if `credit < 0`, it represents the minimum number of uppercase letters required in a password.
    pub fn set_uppercase_credit(&self, credit: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_UP_CREDIT, credit);
            assert!(res == 0);
        }
    }

    /// Returns the uppercase letter credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having uppercase letters in a password;
    ///  - if `credit < 0`, it represents the minimum number of uppercase letters required in a password.
    pub fn get_uppercase_credit(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_UP_CREDIT, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the lowercase letter credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having lowercase letters in a password;
    ///  - if `credit < 0`, it represents the minimum number of lowercase letters required in a password.
    pub fn set_lowercase_credit(&self, credit: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_LOW_CREDIT, credit);
            assert!(res == 0);
        }
    }

    /// Returns the lowercase letter credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having lowercase letters in a password;
    ///  - if `credit < 0`, it represents the minimum number of lowercase letters required in a password.
    pub fn get_lowercase_credit(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_LOW_CREDIT, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the other character credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having other characters in a password;
    ///  - if `credit < 0`, it represents the minimum number of other characters required in a password.
    pub fn set_other_credit(&self, credit: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_OTH_CREDIT, credit);
            assert!(res == 0);
        }
    }

    /// Returns the other character credit:
    ///
    ///  - if `credit >= 0`, it represents the maximum credit for having other characters in a password;
    ///  - if `credit < 0`, it represents the minimum number of other characters required in a password.
    pub fn get_other_credit(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_OTH_CREDIT, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the minimum required number of classes in a password.
    /// There a four available classes:
    ///
    ///  - digits: `[0-9]`
    ///  - lowercase letters: `[a-z]`
    ///  - uppercase letters: `[A-Z]`
    ///  - other characters: `!$%&#…`
    pub fn set_min_classes(&self, min: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_MIN_CLASS, min);
            assert!(res == 0);
        }
    }

    /// Returns the minimum required number of classes in a password.
    pub fn get_min_classes(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_MIN_CLASS, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the maximum size of allowed repeated characters sequences in a password.
    /// A value of `0` disables this check.
    pub fn set_max_repeat(&self, max: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_MAX_REPEAT, max);
            assert!(res == 0);
        }
    }

    /// Returns the maximum size of allowed repeated characters sequences in a password.
    pub fn get_max_repeat(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_MAX_REPEAT, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the maximum size of allowed characters sequences of a same class in a
    /// password.
    /// A value of `0` disables this check,
    pub fn set_max_class_repeat(&self, max: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_MAX_CLASS_REPEAT, max);
            assert!(res == 0);
        }
    }

    /// Returns the maximum size of allowed characters sequences of a same class in a
    /// password.
    pub fn get_max_class_repeat(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_MAX_CLASS_REPEAT, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets the maximum size allowed for monotonic character sequences such as `12345` or `fedcb`
    /// in a password.
    /// A value of `0` disables this check.
    pub fn set_max_sequence(&self, max: i32) {
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_MAX_SEQUENCE, max);
            assert!(res == 0);
        }
    }

    /// Returns the maximum size allowed for monotonic character sequences such as `12345` or `fedcb`
    /// in a password.
    pub fn get_max_sequence(&self) -> i32 {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_MAX_SEQUENCE, result);
            assert!(res == 0);
            *result
        }
    }

    /// Sets whether the check for the presence of words longer than 3 characters present in the
    /// `passwd` GECOS field of a user in a password is enabled.
    pub fn set_gecos_check(&self, check: bool) {
        let value = if check { 1 } else { 0 };
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_GECOS_CHECK, value);
            assert!(res == 0);
        }
    }

    /// Returns whether the check for the presence of words longer than 3 characters present in the
    /// `passwd` GECOS field of a user in a password is enabled.
    pub fn get_gecos_check(&self) -> bool {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_GECOS_CHECK, result);
            assert!(res == 0);
            *result != 0
        }
    }

    /// Sets whether the check that a password is contained in a dictionary is enabled.
    pub fn set_dictionary_check(&self, check: bool) {
        let value = if check { 1 } else { 0 };
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_DICT_CHECK, value);
            assert!(res == 0);
        }
    }

    /// Returns whether the check that a password is contained in a dictionary is enabled.
    pub fn get_dictionary_check(&self) -> bool {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_DICT_CHECK, result);
            assert!(res == 0);
            *result != 0
        }
    }

    /// Sets whether the check of username presence in a password is enabled.
    pub fn set_user_check(&self, check: bool) {
        let value = if check { 1 } else { 0 };
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_USER_CHECK, value);
            assert!(res == 0);
        }
    }

    /// Returns whether the check of username presence in a password is enabled.
    pub fn get_user_check(&self) -> bool {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_USER_CHECK, result);
            assert!(res == 0);
            *result != 0
        }
    }

    /// Sets whether a password that does not pass the checks should be rejected.
    pub fn set_enforcing(&self, check: bool) {
        let value = if check { 1 } else { 0 };
        unsafe {
            let res = pwquality_set_int_value(self.pwq, PWQ_SETTING_ENFORCING, value);
            assert!(res == 0);
        }
    }

    /// Returns whether a password that does not pass the checks should be rejected.
    pub fn get_enforcing(&self) -> bool {
        unsafe {
            let result: *mut i32 = &mut 0;
            let res = pwquality_get_int_value(self.pwq, PWQ_SETTING_ENFORCING, result);
            assert!(res == 0);
            *result != 0
        }
    }

    /// Sets the path to the dictionary to use (other than the default cracklib one).
    pub fn set_dictionary_path(&self, path: String) -> Result<(), Error>{
        let c_path = CString::new(path.as_str()).unwrap();
        unsafe {
            let res = pwquality_set_str_value(self.pwq, PWQ_SETTING_DICT_PATH, c_path.as_ptr());
            if res == 0 {
                Ok(())
            } else {
                Err(Error::from_int(res))
            }
        }
    }

    /// Returns the path to the dictionary to use (if any other than the default cracklib one).
    pub fn get_dictionary_path(&self) -> Result<Option<String>, Error> {
        let (res, ptr) =
            unsafe {
                let mut result = 0 as *mut c_char;
                let res = pwquality_get_str_value(self.pwq, PWQ_SETTING_DICT_PATH, (&mut result) as *mut _ as *mut *mut c_char);
                (res, result)
            };
        if res < 0 {
            Err(Error::from_int(res))
        } else if ptr == (0 as *mut c_char) {
            Ok(None)
        } else {
            let str = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
            Ok(Some(str))
        }
    }

    /// Sets the list of words longer than 3 characters that are not allowed in a password.
    /// Words cannot contain whitespaces, otherwise will be considered as separate words.
    pub fn set_bad_words(&self, bad_words: Vec<String>) -> Result<(), Error> {
        let joined_str = bad_words.join(" ");
        let c_str = CString::new(joined_str.as_str()).unwrap();
        unsafe {
            let res = pwquality_set_str_value(self.pwq, PWQ_SETTING_BAD_WORDS, c_str.as_ptr());
            if res == 0 {
                Ok(())
            } else {
                Err(Error::from_int(res))
            }
        }
    }

    /// Returns the list of forbidden words in a password.
    pub fn get_bad_words(&self) -> Result<Vec<String>, Error> {
        let (res, ptr) =
            unsafe {
                let mut result = 0 as *mut c_char;
                let res = pwquality_get_str_value(self.pwq, PWQ_SETTING_BAD_WORDS, (&mut result) as *mut _ as *mut *mut c_char);
                (res, result)
            };
        if res < 0 {
            Err(Error::from_int(res))
        } else if ptr == (0 as *mut c_char) {
            Ok(vec![])
        } else {
            let str = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
            let result = str.split_whitespace().map(String::from).collect();
            Ok(result)
        }
    }

    /// Generates a password with the given number of bits of entropy.
    pub fn generate_password(&self, entropy: i32) -> Result<String, Error> {
        let (res, ptr) =
            unsafe {
                let mut result = 0 as *mut c_char;
                let res = pwquality_generate(self.pwq, entropy, (&mut result) as *mut _ as *mut *mut c_char);
                (res, result)
            };
        if res < 0 {
            Err(Error::from_int(res))
        } else if ptr == (0 as *mut c_char) {
            Ok("".to_owned())
        } else {
            let pwd = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
            Ok(pwd)
        }
    }

    /// Checks a password according to the settings and returns the computed score.
    pub fn check(&self, password: String, old_password: Option<String>, username: Option<String>) -> Result<i32, Error> {
        unsafe {
            let c_password = CString::new(password).unwrap();
            let res =
                match (old_password, username) {
                    (Some(old_password), Some(username)) => {
                        let c_old_password = CString::new(old_password).unwrap();
                        let c_user = CString::new(username).unwrap();
                        pwquality_check(self.pwq, c_password.as_ptr(), c_old_password.as_ptr(), c_user.as_ptr(), null_mut())
                    },
                    (Some(old_password), None) => {
                        let c_old_password = CString::new(old_password).unwrap();
                        pwquality_check(self.pwq, c_password.as_ptr(), c_old_password.as_ptr(), null(), null_mut())
                    },
                    (None, Some(username)) => {
                        let c_user = CString::new(username).unwrap();
                        pwquality_check(self.pwq, c_password.as_ptr(), null(), c_user.as_ptr(), null_mut())
                    },
                    (None, None) =>
                        pwquality_check(self.pwq, c_password.as_ptr(), null(), null(), null_mut())
                };
            if res < 0 {
                Err(Error::from_int(res))
            } else {
                Ok(res)
            }
        }
    }

}

impl Drop for PWQuality {
    fn drop(&mut self) {
        unsafe {
            // free the memory allocated in the C library
            pwquality_free_settings(self.pwq);
        }
    }
}
