
pub fn resolve_one_of_two_options_or_default<T: Clone>(
    primary: &Option<T>,
    secondary: &Option<T>,
    default: T,
) -> T {
    if let Some(value) = primary {
        value.clone()
    } else if let Some(value) = secondary {
        value.clone()
    } else {
        default
    }
}

pub fn resolve_one_of_two_hex_32_byte_options_or_error(
    cli_option: Option<String>,
    config_option: Option<String>,
    error_message: &str,
) -> anyhow::Result<[u8; 32]> {
    let hex_string = resolve_one_of_two_options_or_error(&cli_option, &config_option, error_message)?;
    let bytes = hex::decode(hex_string.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes (64 hex characters)");
    }
    let byte_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes (64 hex characters)"))?;
    Ok(byte_array)
}

pub fn resolve_one_of_two_options_or_error<T: Clone>(
    primary: &Option<T>,
    secondary: &Option<T>,
    message: &str,
) -> anyhow::Result<T> {
    if let Some(value) = primary {
        Ok(value.clone())
    } else if let Some(value) = secondary {
        Ok(value.clone())
    } else {
        anyhow::bail!("{}", message);
    }
}
