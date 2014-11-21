package main

import (
	"bytes"
	"fmt"
)

func challenge_1_8() {
	for l, line := range lines_in_file("inputs/1-8.txt") {
		if is_ecb(from_base64(line)) {
			fmt.Println("Line", l, "is ECB encoded")
			return
		}
	}
}

func count_ecb_blocks(ciphertext []byte) int {
	blocks := split_blocks(ciphertext, 16)
	same_block := 0

	for i, b1 := range blocks {
		for _, b2 := range blocks[i+1:] {
			if bytes.Equal(b1, b2) {
				same_block++
			}
		}
	}

	return same_block
}

func is_ecb(ciphertext []byte) bool {
	return count_ecb_blocks(ciphertext) > 0
}
