#[cfg(test)]
#[macro_use]
mod tests {
    macro_rules! check_serde {
        ($item:ident: $type:ident in $encoded:ident[$start:literal..$end:literal]) => {
            let encoded = &$encoded[$start..$end];
            check_serde!($item: $type in encoded);
        };
        ($item:ident: $type:ident in $encoded:ident) => {
            let encoded = &$encoded[..];

            println!(concat!(stringify!($item), " check..."));

            let serialized = serde_asn1_der::to_vec(&$item).expect(concat!(
                "failed ",
                stringify!($item),
                " serialization"
            ));
            pretty_assertions::assert_eq!(
                serialized, encoded,
                concat!("serialized ", stringify!($item), " doesn't match")
            );

            let deserialized: $type = serde_asn1_der::from_bytes(encoded).expect(concat!(
                "failed ",
                stringify!($item),
                " deserialization"
            ));
            pretty_assertions::assert_eq!(
                deserialized, $item,
                concat!("deserialized ", stringify!($item), " doesn't match")
            );
        };
    }
}
