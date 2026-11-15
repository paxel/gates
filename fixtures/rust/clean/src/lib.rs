//! The clean Rust fixture: passes every Rust gate.

/// Adds two numbers, `None` on overflow.
#[must_use]
pub fn add(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds_and_refuses_overflow() {
        assert_eq!(add(2, 3), Some(5));
        assert_eq!(add(u32::MAX, 1), None);
    }
}
