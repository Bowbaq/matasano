package main

import (
	"bytes"
	"math/rand"
	"time"
)

func challenge_2_14() {
	rand.Seed(time.Now().UnixNano())
	ecb_oracle_key := random_bytes(16)
	prefix := random_bytes(rand.Intn(100) + 50)
	suffix := from_base64(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)

	ecb_oracle := func(data []byte) []byte {
		return ecb_encrypt(append(prefix, append(data, suffix...)...), ecb_oracle_key)
	}

	discovered := crack_ecb(ecb_oracle)
	assert_equal(suffix, discovered)
}

func crack_ecb(oracle func(data []byte) []byte) []byte {
	block_size := find_ecb_block_size(oracle)
	prefix_len := find_ecb_prefix_len(oracle, block_size)
	unknown_len := len(oracle([]byte{})) - prefix_len
	filler_len := block_size - prefix_len%block_size

	filler := bytes.Repeat([]byte("A"), filler_len)
	known := bytes.Repeat([]byte("A"), block_size)
	padding := bytes.Repeat([]byte("A"), block_size-1)

	needle_block := (prefix_len + filler_len) / block_size

	for next_byte := 0; next_byte < unknown_len; next_byte++ {
		input := bytes.Join([][]byte{filler, append(known[next_byte+1:], 0), padding[next_byte%block_size:]}, nil)

		target := needle_block + next_byte/block_size + 1
		for b := byte(0); b < 255; b++ {
			input[block_size+filler_len-1] = b
			output_blocks := split_blocks(oracle(input), block_size)

			if bytes.Equal(output_blocks[needle_block], output_blocks[target]) {
				known = append(known, b)
				break
			}
		}
	}

	return bytes.TrimRight(known[block_size:], "\x04")
}

func find_ecb_prefix_len(ecb_oracle func(data []byte) []byte, block_size int) int {
	base := split_blocks(ecb_oracle([]byte{}), block_size)
	diff := split_blocks(ecb_oracle([]byte{0}), block_size)

	block_len := 0
	for i := 0; i < len(base); i++ {
		if bytes.Equal(base[i], diff[i]) {
			block_len++
			continue
		}
		// found the differing block
		prev := make([]byte, block_size)
		for j := block_size; j <= block_size*2; j++ {
			diff = split_blocks(ecb_oracle(bytes.Repeat([]byte("A"), j)), block_size)
			if bytes.Equal(diff[i+1], prev) {
				return (block_len+2)*block_size - j + 1
			} else {
				copy(prev, diff[i+1])
			}
		}
		return block_len * block_size
	}

	return -1
}
