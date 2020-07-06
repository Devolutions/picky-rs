macro_rules! serde_invalid_value {
    ($typ:ident, $unexp:literal, $exp:literal) => {{
        const _: Option<$typ> = None;
        de::Error::invalid_value(
            serde::de::Unexpected::Other(concat!("[", stringify!($typ), "] ", $unexp)),
            &$exp,
        )
    }};
}

macro_rules! seq_next_element {
    ($seq:ident, $typ:ident, $missing_elem:literal) => {{
        const _: Option<$typ> = None;
        $seq.next_element()?.ok_or_else(|| {
            de::Error::invalid_value(
                serde::de::Unexpected::Other(concat!("[", stringify!($typ), "] ", $missing_elem, " is missing")),
                &concat!("valid ", $missing_elem),
            )
        })?
    }};
    ($seq:ident, $typ_hint:path, $typ:ident, $missing_elem:literal) => {{
        const _: Option<$typ> = None;
        $seq.next_element::<$typ_hint>()?.ok_or_else(|| {
            de::Error::invalid_value(
                serde::de::Unexpected::Other(concat!("[", stringify!($typ), "] ", $missing_elem, " is missing")),
                &concat!("valid ", $missing_elem),
            )
        })?
    }};
}

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

            let serialized = picky_asn1_der::to_vec(&$item).expect(concat!(
                "failed ",
                stringify!($item),
                " serialization"
            ));
            pretty_assertions::assert_eq!(
                serialized, encoded,
                concat!("serialized ", stringify!($item), " doesn't match")
            );

            let deserialized: $type = picky_asn1_der::from_bytes(encoded).expect(concat!(
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
