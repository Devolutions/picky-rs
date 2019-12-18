/// A trait to parse the test-vector strings
#[doc(hidden)]
pub trait ParseStr {
    /// Parses the string `to_parse` at `line` to `Self` or panics
    fn parse_str(line: usize, to_parse: &'static str) -> Self;
}
impl ParseStr for &'static str {
    fn parse_str(_line: usize, to_parse: &'static str) -> Self {
        to_parse
    }
}
impl ParseStr for usize {
    fn parse_str(line: usize, to_parse: &'static str) -> Self {
        use std::str::FromStr;
        usize::from_str(to_parse).unwrap_or_else(|_| panic!("Test vector contains invalid usize @{}", line))
    }
}
impl ParseStr for bool {
    fn parse_str(line: usize, to_parse: &'static str) -> Self {
        use std::str::FromStr;
        bool::from_str(to_parse).unwrap_or_else(|_| panic!("Test vector contains invalid usize @{}", line))
    }
}
impl ParseStr for u128 {
    fn parse_str(line: usize, to_parse: &'static str) -> Self {
        use std::str::FromStr;
        u128::from_str(to_parse).unwrap_or_else(|_| panic!("Test vector contains invalid usize @{}", line))
    }
}
impl ParseStr for () {
    fn parse_str(line: usize, to_parse: &'static str) -> Self {
        if to_parse != "()" {
            panic!("Test vector contains invalid unit type @{}", line)
        }
        ()
    }
}
impl ParseStr for Vec<u8> {
    fn parse_str(line: usize, to_parse: &'static str) -> Self {
        // Helper to decode a hex-encoded nibble
        let decode = |nibble: u8| -> u8 {
            match nibble {
                n @ b'0'..=b'9' => n - b'0',
                n @ b'a'..=b'f' => (n - b'a') + 10,
                n @ b'A'..=b'F' => (n - b'A') + 10,
                n => panic!("Test vector contains invalid hex char \"{:02x}\" @{}", n, line),
            }
        };

        // Decode the string
        assert_eq!(
            to_parse.len() % 2,
            0,
            "Test vector contains invalid hex string @{}",
            line
        );
        to_parse.as_bytes().chunks(2).fold(Self::new(), |mut vec, pair| {
            vec.push(decode(pair[0]) << 4 | decode(pair[1]));
            vec
        })
    }
}
impl ParseStr for serde_bytes::ByteBuf {
    fn parse_str(line: usize, to_parse: &'static str) -> Self {
        serde_bytes::ByteBuf::from(Vec::parse_str(line, to_parse))
    }
}
impl ParseStr for String {
    fn parse_str(_line: usize, to_parse: &'static str) -> Self {
        to_parse.to_string()
    }
}

/// Reads the test vectors at `$path`
#[macro_export]
macro_rules! read_test_vectors {
	($path:expr => $struct:ident { line, $($field_name:ident),+ }) => ({
		// Helper to parse a line
		fn parse_line<T: ParseStr>(key: &str, (line, text): (usize, &'static str)) -> T {
			// Validate that the lines starts with `key` and extracts the value-substring
			let key = format!("{}:", key);
			let text = match text.starts_with(&key) {
				true => text.split_at(key.len()).1.trim(),
				false => panic!("Invalid line-key @{}", line)
			};

			// Decode the string
			T::parse_str(line, text)
		}

		// Enumerate the lines and ignore empty and comment lines
		let mut lines = include_str!($path).lines().enumerate()
			.filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
			.peekable();

		// Let line number
		let mut structs = Vec::new();
		loop {
			// Check if we have a next test vector
			let line = match lines.peek() {
				Some((line, _)) => *line + 1,
				None => break structs
			};

			// Parse test vector
			structs.push($struct {
				line,
				$($field_name: parse_line(
					stringify!($field_name),
					lines.next().unwrap_or_else(|| panic!("Incomplete test vector @{}", line))
				)),+
			})
		}
	});
}
