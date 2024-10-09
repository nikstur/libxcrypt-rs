use xcrypt::{crypt, crypt_gensalt};

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
