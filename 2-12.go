package main

import (
	"bytes"
	"log"
)

var ecb_oracle_key = random_bytes(16)

func challenge_2_12() {
	block_size := find_block_size()
	log.Println(block_size)

	// input := bytes.Repeat([]byte("A"), block_size*2-1)
	// var first byte
	// for b := byte(0); b < 255; b++ {
	// 	input[block_size-1] = b
	// 	output := ecb_oracle(input)
	// 	if bytes.Equal(output[:block_size], output[block_size:block_size*2]) {
	// 		first = b
	// 		break
	// 	}
	// }

	// input := bytes.Repeat([]byte("A"), block_size*2-2)
	// for b := byte(0); b < 255; b++ {
	// 	input[block_size-2] = first
	// 	input[block_size-1] = b
	// 	output := ecb_oracle(input)
	// 	if bytes.Equal(output[:block_size], output[block_size:block_size*2]) {
	// 		log.Println("Found", string(b))
	// 		break
	// 	}
	// }
}

func ecb_oracle(data []byte) []byte {
	suffix := from_base64(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)
	return ecb_encrypt(append(data, suffix...), ecb_oracle_key)
}

func find_block_size() int {
	l := 1
	ecb_l := 0
	ecb_blocks := 0
	for {
		detected_blocks := count_ecb_blocks(ecb_oracle(bytes.Repeat([]byte("A"), l)))
		if detected_blocks > ecb_blocks {
			if ecb_blocks == 0 {
				ecb_l = l
				ecb_blocks = detected_blocks
			} else {
				return l - ecb_l
			}
		}
		l++
	}

	return -1
}
