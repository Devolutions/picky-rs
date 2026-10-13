macro_rules! names {
    ($($area:ident),* $(,)?) => {
        vec![$(stringify!($area)),*]
    };
}

fn modules(dir: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(dir);
    let mut names: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| name.strip_suffix(".rs").map(str::to_owned))
        .filter(|name| name != "mod")
        .collect();
    names.sort();
    names
}

// Catches an area module that the runner list macros leave out, which would silently skip it.
#[test]
fn list_macros_name_every_area_module() {
    for (dir, mut listed) in [
        ("areas", picky_crypto_testsuite::for_each_area!(names)),
        (
            "differential",
            picky_crypto_testsuite::for_each_differential_area!(names),
        ),
    ] {
        listed.sort_unstable();
        assert_eq!(listed, modules(dir), "src/{dir}");
    }
}
