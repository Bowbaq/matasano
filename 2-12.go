package main

func challenge_2_12() {
	ecb_oracle_key := random_bytes(16)
	suffix := from_base64(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)

	ecb_oracle := func(data []byte) []byte {
		return ecb_encrypt(append(data, suffix...), ecb_oracle_key)
	}

	assert_equal(suffix, crack_ecb(ecb_oracle))
}
