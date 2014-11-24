package main

import "bytes"

var (
	ecb_oracle_key = random_bytes(16)
	suffix         = from_base64(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
)

func challenge_2_12() {
	block_size := find_block_size()
	unknown_len := len(ecb_oracle([]byte{}))

	known := bytes.Repeat([]byte("A"), block_size)
	padding := bytes.Repeat([]byte("A"), block_size-1)

	for next_byte := 0; next_byte < unknown_len; next_byte++ {
		input := append(append(known[next_byte+1:], 0), padding[next_byte%block_size:]...)
		block := next_byte/block_size + 1
		for b := byte(0); b < 255; b++ {
			input[block_size-1] = b
			output := ecb_oracle(input)
			if bytes.Equal(output[:block_size], output[block_size*block:block_size*(block+1)]) {
				known = append(known, b)
				break
			}
		}
	}

	known = pcks_unpad(known[block_size:], block_size)

	assert_equal(suffix, known)
}

func ecb_oracle(data []byte) []byte {
	return ecb_encrypt(append(data, suffix...), ecb_oracle_key)
}

func find_block_size() int {
	var (
		last_ecb_len   int
		last_ecb_count int
		needle         []byte
	)

	for {
		needle = append(needle, byte('A'))
		if count := ecb_count(ecb_oracle(needle)); count > last_ecb_count {
			if last_ecb_count == 0 {
				last_ecb_count = count
				last_ecb_len = len(needle)
			} else {
				return len(needle) - last_ecb_len
			}
		}
	}

	return -1
}
