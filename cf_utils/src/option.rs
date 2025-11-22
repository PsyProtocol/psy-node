
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
