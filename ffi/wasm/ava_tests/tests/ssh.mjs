import test from "ava";
import { SshPrivateKey, EcCurve } from "@devolutions/picky";

function key_roundtrip(t, key) {
	const pem_generated = key.to_pem();

	const key_parsed = SshPrivateKey.from_pem(pem_generated, "test");
	const pem_parsed = key_parsed.to_pem();

	t.is(pem_parsed.to_repr(), pem_generated.to_repr());
}

test("Generate and parse RSA SSH key", (t) => {
	try {
		const key = SshPrivateKey.generate_rsa(2048, "test", "test@picky.com");
		key_roundtrip(t, key);
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});

test("Generate and parse EC SSH key", (t) => {
	try {
		const key = SshPrivateKey.generate_ec(
			EcCurve.NistP256,
			"test",
			"test@picky.com",
		);
		key_roundtrip(t, key);
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});

test("Generate and parse ED25519 SSH key", (t) => {
	try {
		const key = SshPrivateKey.generate_ed25519("test", "test@picky.com");
		key_roundtrip(t, key);
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});
