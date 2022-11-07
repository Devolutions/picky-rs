import test from "ava";
import {
	PrivateKey,
	Pem,
	JwtSig,
	JwtValidator,
	JwsAlg,
} from "@devolutions/picky";

const PRIV_KEY_PEM_REPR = [
	"-----BEGIN PRIVATE KEY-----",
	"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkrPiL/5dmGIT5",
	"/KuC3H/jIjeLoLoddsLhAlikO5JQQo3Zs71GwT4Wd2z8WLMe0lVZu/Jr2S28p0M8",
	"F3Lnz4IgzjocQomFgucFWWQRyD03ZE2BHfEeelFsp+/4GZaM6lKZauYlIMtjR1vD",
	"lflgvxNTr0iaii4JR9K3IKCunCRy1HQYPcZ9waNtlG5xXtW9Uf1tLWPJpP/3I5HL",
	"M85JPBv4r286vpeUlfQIa/NB4g5w6KZ6MfEAIU4KeEQpeLAyyYvwUzPR2uQZ4y4I",
	"4Nj84dWYB1cMTlSGugvSgOFKYit1nwLGeA7EevVYPbILRfSMBU/+avGNJJ8HCaaq",
	"FIyY42W9AgMBAAECggEBAImsGXcvydaNrIFUvW1rkxML5qUJfwN+HJWa9ALsWoo3",
	"h28p5ypR7S9ZdyP1wuErgHcl0C1d80tA6BmlhGhLZeyaPCIHbQQUa0GtL7IE+9X9",
	"bSvu+tt+iMcB1FdqEFmGOXRkB2sS82Ax9e0qvZihcOFRBkUEK/MqapIV8qctGkSG",
	"wIE6yn5LHRls/fJU8BJeeqJmYpuWljipwTkp9hQ7SdRYFLNjwjlz/b0hjmgFs5QZ",
	"LUNMyTHdHtXQHNsf/GayRUAKf5wzN/jru+nK6lMob2Ehfx9/RAfgaDHzy5BNFMj0",
	"i9+sAycgIW1HpTuDvSEs3qP26NeQ82GbJzATmdAKa4ECgYEA9Vti0YG+eXJI3vdS",
	"uXInU0i1SY4aEG397OlGMwh0yQnp2KGruLZGkTvqxG/Adj1ObDyjFH9XUhMrd0za",
	"Nk/VJFybWafljUPcrfyPAVLQLjsBfMg3Y34sTF6QjUnhg49X2jfvy9QpC5altCtA",
	"46/KVAGREnQJ3wMjfGGIFP8BUZsCgYEA7phYE/cYyWg7a/o8eKOFGqs11ojSqG3y",
	"0OE7kvW2ugUuy3ex+kr19Q/8pOWEc7M1UEV8gmc11xgB70EhIFt9Jq379H0X4ahS",
	"+mgLiPzKAdNCRPpkxwwN9HxFDgGWoYcgMplhoAmg9lWSDuE1Exy8iu5inMWuF4MT",
	"/jG+cLnUZ4cCgYAfMIXIUjDvaUrAJTp73noHSUfaWNkRW5oa4rCMzjdiUwNKCYs1",
	"yN4BmldGr1oM7dApTDAC7AkiotM0sC1RGCblH2yUIha5NXY5G9Dl/yv9pHyU6zK3",
	"UBO7hY3kmA611aP6VoACLi8ljPn1hEYUa4VR1n0llmCm29RH/HH7EUuOnwKBgExH",
	"OCFp5eq+AAFNRvfqjysvgU7M/0wJmo9c8obRN1HRRlyWL7gtLuTh74toNSgoKus2",
	"y8+E35mce0HaOJT3qtMq3FoVhAUIoz6a9NUevBZJS+5xfraEDBIViJ4ps9aANLL4",
	"hlV7vpICWWeYaDdsAHsKK0yjhjzOEx45GQFA578RAoGBAOB42BG53tL0G9pPeJPt",
	"S2LM6vQKeYx+gXTk6F335UTiiC8t0CgNNQUkW105P/SdpCTTKojAsOPMKOF7z4mL",
	"lj/bWmNq7xu9uVOcBKrboVFGO/n6FXyWZxHPOTdjTkpe8kvvmSwl2iaTNllvSr46",
	"Z/fDKMxHxeXla54kfV+HiGkH",
	"-----END PRIVATE KEY-----",
].join("\n");

const CLAIMS = JSON.stringify({
	admin: true,
	exp: 1516539022,
	iat: 1516239022,
	name: "John Doe",
	nbf: 1516239022,
});

const HEADER_SECTION =
	"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFVVEgiLCJraWQiOiJtYXN0ZXIta2V5In0";

const PAYLOAD_SECTION =
	"eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNTE2NTM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsIm5iZiI6MTUxNjIzOTAyMn0";

const SIGNED_JWT =
	"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFVVEgiLCJraWQiOiJtYXN0ZXIta2V5In0.eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNTE2NTM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsIm5iZiI6MTUxNjIzOTAyMn0.wqZcddQCA2UZj8-pT5GRj1GCTJWwVlE6uHgjMq18vctvmzNVYD34ri4-61qW460J64JmG5ZYwqOedNSlSqCl3lY63BkXrSRYOKnwWJTwoljz3BrLKx4t6jeBTJVMFLs7JiiCoxNc2uq33qh8F08cV_2fjALvgBdm3pkFgm-y-P07fBYLnXcuP5-OOMvynQmoqXd2zm-XH1YbwTW_8LYoJH_Aqfgyqfrcs1BEzJEGJUtL-HPictnswutW9c1dvwgI5Tr7PdltTu7hRuJof7ojZYDADg_aaecjzsI1zXu0NU_-DwAzrPaR5QTaDTTNyJRPwDjr7l0Dtdq5USMt48bSNg";

test("Smoke", (t) => {
	try {
		const builder = JwtSig.builder();
		builder.set_kid("master-key");
		builder.set_content_type("AUTH");
		builder.set_claims(CLAIMS);

		const jwt = builder.build();
		t.is(jwt.get_kid(), "master-key");
		t.is(jwt.get_content_type(), "AUTH");
		t.is(jwt.get_claims(), CLAIMS);

		const pem = Pem.parse(PRIV_KEY_PEM_REPR);
		const priv = PrivateKey.from_pem(pem);
		const encoded = jwt.encode(priv);
		const parts = encoded.split(".");
		t.is(parts[0], HEADER_SECTION);
		t.is(parts[1], PAYLOAD_SECTION);
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});

test("Decode Signed JWT", (t) => {
	try {
		const pem = Pem.parse(PRIV_KEY_PEM_REPR);
		const key = PrivateKey.from_pem(pem).to_public_key();
		const validator = JwtValidator.strict(BigInt(1516259022), 0);
		const jwt = JwtSig.decode(SIGNED_JWT, key, validator);
		t.is(jwt.get_kid(), "master-key");
		t.is(jwt.get_content_type(), "AUTH");
		t.is(jwt.get_claims(), CLAIMS);
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});

test("Additional Header Parameters", (t) => {
	try {
		const additionalObject = {
			answer: 42,
			foo: "bar",
		};

		const builder = JwtSig.builder();
		builder.set_algorithm(JwsAlg.RS512);
		builder.set_claims(CLAIMS);
		builder.add_additional_parameter_string(
			"additional_token",
			"abcd.efgh.ijklm",
		);
		builder.add_additional_parameter_object(
			"additional_object",
			JSON.stringify(additionalObject),
		);
		builder.add_additional_parameter_pos_int("additional_number", BigInt(64));
		builder.add_additional_parameter_neg_int(
			"additional_negative_number",
			BigInt(-64),
		);

		const jwt = builder.build();

		{
			t.is(jwt.get_claims(), CLAIMS);

			const header = JSON.parse(jwt.get_header());
			t.deepEqual(header.additional_object, additionalObject);
			t.is(header.alg, "RS512");
			t.is(header.typ, "JWT");
			t.is(header.additional_token, "abcd.efgh.ijklm");
			t.is(header.additional_number, 64);
			t.is(header.additional_negative_number, -64);
		}

		const pem = Pem.parse(PRIV_KEY_PEM_REPR);
		const priv = PrivateKey.from_pem(pem);
		const encoded = jwt.encode(priv);

		{
			const parts = encoded.split(".");
			t.is(PAYLOAD_SECTION, parts[1]);

			// Decode header part (url-safe base64-encoded)
			const headerPart = atob(parts[0].replace("-", "+").replace("_", "/"));
			const header = JSON.parse(headerPart);

			t.deepEqual(header.additional_object, additionalObject);
			t.is(header.alg, "RS512");
			t.is(header.typ, "JWT");
			t.is(header.additional_token, "abcd.efgh.ijklm");
			t.is(header.additional_number, 64);
			t.is(header.additional_negative_number, -64);
		}
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});
