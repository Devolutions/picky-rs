Rule:
1. Never implement drop for opaque or opaque_mut type, this is a known limitation for Upstream Diplomat
2. Only mark `manually_disposable` for 1.memory-heavy types and 2.the sensitive data
