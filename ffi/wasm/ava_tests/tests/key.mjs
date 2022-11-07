import test from "ava";
import { PrivateKey, Pem } from "@devolutions/picky";

const privKeyPemRepr = [
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

const pubKeyPemRepr = [
	"-----BEGIN PUBLIC KEY-----",
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Kz4i/+XZhiE+fyrgtx/",
	"4yI3i6C6HXbC4QJYpDuSUEKN2bO9RsE+Fnds/FizHtJVWbvya9ktvKdDPBdy58+C",
	"IM46HEKJhYLnBVlkEcg9N2RNgR3xHnpRbKfv+BmWjOpSmWrmJSDLY0dbw5X5YL8T",
	"U69ImoouCUfStyCgrpwkctR0GD3GfcGjbZRucV7VvVH9bS1jyaT/9yORyzPOSTwb",
	"+K9vOr6XlJX0CGvzQeIOcOimejHxACFOCnhEKXiwMsmL8FMz0drkGeMuCODY/OHV",
	"mAdXDE5UhroL0oDhSmIrdZ8CxngOxHr1WD2yC0X0jAVP/mrxjSSfBwmmqhSMmONl",
	"vQIDAQAB",
	"-----END PUBLIC KEY-----",
].join("\n");

test("Private Key to Public Key", (t) => {
	try {
		const pem = Pem.parse(privKeyPemRepr);
		const priv = PrivateKey.from_pem(pem);
		const pub = priv.to_public_key();
		t.is(pubKeyPemRepr, pub.to_pem().to_repr());
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});

test("Generate RSA keypair", (t) => {
	try {
		const key = PrivateKey.generate_rsa(2048);
		const pem = key.to_pem();
		t.is(pem.get_label(), "PRIVATE KEY");
	} catch (e) {
		if (typeof e.to_display === "undefined") {
			throw e;
		} else {
			throw e.to_display();
		}
	}
});
