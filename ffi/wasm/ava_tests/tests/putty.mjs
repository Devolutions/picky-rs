import test from "ava";
import { PuttyPpk } from "@devolutions/picky";

function key_roundtrip(t, original) {
	const original_str = original.to_string();

	let encrypted = original.encrypt("test");

	let encrypted_str = encrypted.to_repr();

	let encryted_parsed = PuttyPpk.parse(encrypted_str);
	let decrypted = encryted_parsed.decrypt("test");

	let after_roundtrip = decrypted.to_repr();

	t.is(after_roundtrip, original_str);
}

// NOTE: We test only ED25519 case because inner key generation is based on ssh module code
// internally.

test("Generate and parse ED25519 PuTTY key", (t) => {
	try {
		const key = PuttyPpk.generate_ed25519("test", "test@picky.com");
		key_roundtrip(t, key);
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});
