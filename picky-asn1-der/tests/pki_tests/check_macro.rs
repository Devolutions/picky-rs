macro_rules! check {
    ($item:ident: $type:ident in $encoded:ident[$start:literal..$end:literal]) => {
        let encoded = &$encoded[$start..$end];
        check!($item: $type in encoded);
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
