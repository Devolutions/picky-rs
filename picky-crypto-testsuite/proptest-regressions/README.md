# Property regressions

Each file holds the shrunk failing cases of one property test, named after the property's ID; proptest replays them before generating new cases.
The properties use a fixed seed, so a regular run reproduces its own failures without these files.
Larger runs, such as the weekly extended run (`PICKY_CRYPTO_TESTSUITE_EXTENDED=1`), try cases a regular run doesn't reach.
proptest writes a `cc` line for each such failure; committing it makes every later run, including regular CI, replay that case.
The weekly run uploads this directory as an artifact when it fails.
