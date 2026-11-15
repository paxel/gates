//! The red Rust fixture: the planted finding is an unwrap in shipped code, which the lint
//! set denies, so the Rust gate must fail.

/// Adds two numbers and panics on overflow.
#[must_use]
pub fn add(a: u32, b: u32) -> u32 {
    a.checked_add(b).unwrap()
}

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds() {
        assert_eq!(add(2, 3), 5);
    }
}
