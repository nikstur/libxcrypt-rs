//! Bindings for libxcrypt.
//!
//! # Examples
//!
//! Hash a phrase with the best available hashing method and default parameters:
//!
//! ```
//! use xcrypt::{crypt, crypt_gensalt};
//!
//! let setting = crypt_gensalt(None, 0, None).unwrap();
//! crypt("hello", &setting);
//! ```
//!
//! You can also explicitly request a specific hashing method:
//!
//! ```
//! use xcrypt::{crypt, crypt_gensalt};
//!
//! let setting = crypt_gensalt(Some("$6$"), 0, None).unwrap();
//! crypt("hello", &setting);
//! ```

use std::{
    ffi::{CStr, CString},
    fmt, io,
};

#[derive(Debug)]
pub enum Error {
    /// And invalid argument was provided.
    InvalidArgument(String),
    /// Input phrase is too long for specified hashing method.
    PhraseTooLong,
    /// No random number generator is available on the platform.
    RngNotAvailable,
    /// An unknown IO error occured.
    IoError(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidArgument(ref msg) => write!(f, "{msg}"),
            Self::PhraseTooLong => {
                write!(f, "Input phrase is too long for specified hashing method")
            }
            Self::RngNotAvailable => {
                write!(f, "No random number generator is available on the platform")
            }
            Self::IoError(..) => {
                write!(f, "An unknown IO error occured")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::IoError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl Error {
    fn invalid_argument(msg: &str) -> Error {
        Self::InvalidArgument(msg.into())
    }
}

/// Compile a string for use as the setting argument to crypt.
///
/// Internally, this calls `crypt_gensalt_rn` so that this function can be called from multiple
/// threads at the same time.
pub fn crypt_gensalt(
    prefix: Option<&str>,
    count: u64,
    random_bytes: Option<&[i8]>,
) -> Result<String, Error> {
    let c_prefix = prefix
        .map(|s| CString::new(s).map_err(|_| Error::invalid_argument("Prefix contains NULL byte")))
        .transpose()?;
    let c_prefix_ptr = match &c_prefix {
        Some(cs) => cs.as_ptr(),
        None => std::ptr::null(),
    };

    let rbytes_ptr = match &random_bytes {
        Some(rb) => rb.as_ptr(),
        None => std::ptr::null(),
    };
    let nrbytes = random_bytes
        .as_ref()
        .map_or(0, |rb| rb.len())
        .try_into()
        .map_err(|_| Error::invalid_argument("Too many random bytes"))?;

    let mut output = [0; xcrypt_sys::CRYPT_GENSALT_OUTPUT_SIZE as usize];
    let output_len = output.len().try_into().map_err(|_| {
        Error::invalid_argument(
            "Output buffer is too big. This is an internal error and should never occur",
        )
    })?;

    let c_settings = unsafe {
        let settings_ptr = xcrypt_sys::crypt_gensalt_rn(
            c_prefix_ptr,
            count,
            rbytes_ptr,
            nrbytes,
            output.as_mut_ptr(),
            output_len,
        );

        let last_os_error = io::Error::last_os_error();
        if let Some(errno) = last_os_error.raw_os_error() {
            if errno > 0 {
                let error = match errno {
                    22 /* EINVAL */  => Error::invalid_argument("Invalid prefix, count, or random_bytes"),
                    88 /* ENOSYS */ | 13 /* ENOSYS */ | 5 /* EIO */ => Error::RngNotAvailable,
                    _ => Error::IoError(last_os_error),
                };
                return Err(error);
            }
        }

        CStr::from_ptr(settings_ptr)
    };

    Ok(c_settings.to_string_lossy().to_string())
}

/// Irreversibly hash `phrase` for storage in the system password database (shadow(5)) using a
/// cryptographic hashing method.
///
/// Internally, this calls `crypt_r` so that this function can be safely called from multiple
/// threads at the same time.
pub fn crypt(phrase: &str, setting: &str) -> Result<String, Error> {
    let mut crypt_data = xcrypt_sys::crypt_data {
        output: [0; xcrypt_sys::CRYPT_OUTPUT_SIZE as usize],
        setting: [0; xcrypt_sys::CRYPT_OUTPUT_SIZE as usize],
        input: [0; xcrypt_sys::CRYPT_MAX_PASSPHRASE_SIZE as usize],
        initialized: 0,
        reserved: [0; xcrypt_sys::CRYPT_DATA_RESERVED_SIZE as usize],
        internal: [0; xcrypt_sys::CRYPT_DATA_INTERNAL_SIZE as usize],
    };

    let c_phrase =
        CString::new(phrase).map_err(|_| Error::invalid_argument("Phrase contains NULL byte"))?;
    let c_setting =
        CString::new(setting).map_err(|_| Error::invalid_argument("Setting contains NULL byte"))?;

    let c_hashed_phrase = unsafe {
        let hashed_phrase_ptr =
            xcrypt_sys::crypt_r(c_phrase.as_ptr(), c_setting.as_ptr(), &mut crypt_data);

        let last_os_error = io::Error::last_os_error();
        if let Some(errno) = last_os_error.raw_os_error() {
            if errno > 0 {
                let error = match errno {
                    22 /* EINVAL */  => Error::invalid_argument("Invalid setting"),
                    34 /* ERANGE */ => Error::PhraseTooLong,
                    _ => Error::IoError(last_os_error),
                };
                return Err(error);
            }
        }

        CStr::from_ptr(hashed_phrase_ptr)
    };
    Ok(c_hashed_phrase.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn crypt_phrase() -> Result<()> {
        let hashed_phrase = crypt("hello", "$y$j9T$VlxJo/WDfFCOPzIIjNMDW.")?;
        assert_eq!(
            hashed_phrase,
            "$y$j9T$VlxJo/WDfFCOPzIIjNMDW.$dsfHohjtMq.tSGo8x8n9EZx9zqVomsGYSfWEyApH1k."
        );
        Ok(())
    }

    #[test]
    fn crypt_phrase_invalid_setting() {
        assert!(crypt("hello", "$").is_err());
    }

    #[test]
    fn gensalt_and_crypt() -> Result<()> {
        let strong_hashing_methods = [
            "$y$", "$gy$",
            // Somehow crypt_r returns ENOMEM for scrypt, which it really shouldn't
            // "$7$",
            "$2b$", "$6$",
        ];
        for hashing_method in strong_hashing_methods {
            let setting = crypt_gensalt(Some(hashing_method), 0, None)?;
            let hashed_phrase = crypt("hello", &setting)?;
            assert!(hashed_phrase.starts_with(hashing_method));
        }
        Ok(())
    }

    #[test]
    fn crypt_gensalt_deterministic() -> Result<()> {
        let mut n = 0x1234_5678_9789_0123_5678_9012u128;
        let mut random_bytes: Vec<i8> = Vec::new();
        while n > 9 {
            let rest = n % 10;
            random_bytes.push(rest as i8);
            n /= 10;
        }
        random_bytes.push(n.try_into()?);

        let setting = crypt_gensalt(Some("$y$"), 0, Some(&random_bytes))?;
        assert_eq!(setting, "$y$j9T$6I..3I..6UE//2U/5EU..I./5MU/0...2AU/3.");
        Ok(())
    }

    #[test]
    fn crypt_gensalt_random() -> Result<()> {
        let setting_1 = crypt_gensalt(Some("$gy$"), 0, None)?;
        let setting_2 = crypt_gensalt(Some("$gy$"), 0, None)?;
        assert_ne!(setting_1, setting_2);
        Ok(())
    }
}
