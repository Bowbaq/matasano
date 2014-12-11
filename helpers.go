package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
)

// Hex stuff
func to_hex(input []byte) string {
	return hex.EncodeToString(input)
}

func from_hex(input string) []byte {
	data, _ := hex.DecodeString(input)
	return data
}

// Base64 stuff
func to_base64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func from_base64(input string) []byte {
	data, _ := base64.StdEncoding.DecodeString(input)
	return data
}

func from_base64_file(filename string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return from_base64(string(data))
}

// XOR
func xor(a, b []byte) []byte {
	xored := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		xored[i] = a[i] ^ b[i]
	}

	return xored
}

func xor_repeat(input []byte, key string) []byte {
	repeating_key := strings.Repeat(key, len(input)/len(key)+1)
	return xor(input, []byte(repeating_key))
}

func find_single_char_xor(input []byte) (string, byte, int) {
	var (
		best_guess string
		best_score int
		best_char  byte
	)

	for c := byte(0); c < 255; c++ {
		guess := string(xor_repeat(input, string(c)))
		score := english_score(guess)
		if score > best_score {
			best_guess = guess
			best_score = score
			best_char = c
		}
	}

	return best_guess, best_char, best_score
}

const freqs = "zqxjkvbpygfwmucldrhs nioate"

func english_score(text string) int {
	var score int
	for _, c := range strings.ToLower(text) {
		score += strings.Index(freqs, string(c))
	}

	return score
}

func avg_hamming_distance(chunks ...[]byte) float64 {
	var (
		sum   float64
		count int
	)

	for i, chunk_a := range chunks {
		for _, chunk_b := range chunks[i+1:] {
			sum += float64(hamming_distance(chunk_a, chunk_b))
			count++
		}
	}

	return sum / float64(count)
}

func hamming_distance(a, b []byte) int {
	var distance int

	for i := 0; i < len(a); i++ {
		bits := a[i] ^ b[i]
		for bits != 0 {
			distance++
			bits &= bits - 1
		}
	}

	return distance
}

func split_blocks(data []byte, ks int) [][]byte {
	var blocks [][]byte
	for i := 0; i+ks < len(data); i += ks {
		blocks = append(blocks, data[i:i+ks])
	}
	blocks = append(blocks, data[len(blocks)*ks:])

	return blocks
}

func transpose(blocks [][]byte) [][]byte {
	ks := len(blocks[0])
	transposed := make([][]byte, ks)

	for i := 0; i < ks; i++ {
		for _, block := range blocks {
			if i < len(block) {
				transposed[i] = append(transposed[i], block[i])
			}
		}
	}

	return transposed
}

// ECB AES
func ecb_decrypt(ciphertext, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += cipher.BlockSize() {
		cipher.Decrypt(plaintext[i:], ciphertext[i:])
	}

	return pcks_unpad(plaintext, cipher.BlockSize())
}

func ecb_encrypt(plaintext, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	ciphertext := make([]byte, 0)

	encrypted := make([]byte, cipher.BlockSize())
	for i := 0; i < len(plaintext); i += cipher.BlockSize() {
		cipher.Encrypt(encrypted, pcks_pad(plaintext[i:], cipher.BlockSize()))
		ciphertext = append(ciphertext, encrypted...)
	}

	return ciphertext
}

func ecb_count(ciphertext []byte) (ecb_count int) {
	blocks := split_blocks(ciphertext, 16)

	for i, b1 := range blocks {
		for _, b2 := range blocks[i+1:] {
			if bytes.Equal(b1, b2) {
				ecb_count++
			}
		}
	}

	return ecb_count
}

func is_ecb(ciphertext []byte) bool {
	return ecb_count(ciphertext) > 0
}

func find_ecb_block_size(ecb_oracle func(data []byte) []byte) int {
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

// CBC AES
func cbc_decrypt(ciphertext, key, iv []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	plaintext := make([]byte, 0)
	decrypted := make([]byte, cipher.BlockSize())

	for _, block := range split_blocks(ciphertext, cipher.BlockSize()) {
		cipher.Decrypt(decrypted, block)
		decrypted = xor(iv, decrypted)
		plaintext = append(plaintext, decrypted...)
		iv = block
	}

	return pcks_unpad(plaintext, cipher.BlockSize())
}

func cbc_encrypt(plaintext, key, iv []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	ciphertext := make([]byte, 0)
	blocks := split_blocks(plaintext, cipher.BlockSize())

	for _, block := range blocks {
		encrypted := xor(iv, pcks_pad(block, cipher.BlockSize()))
		cipher.Encrypt(encrypted, encrypted)
		ciphertext = append(ciphertext, encrypted...)
		iv = encrypted
	}

	return ciphertext
}

// PCKS
func pcks_pad(block []byte, length int) []byte {
	padding_bytes := length - len(block)
	if padding_bytes > 0 {
		return append(block, bytes.Repeat([]byte("\x04"), padding_bytes)...)
	}
	return block
}

func pcks_unpad(data []byte, block_size int) []byte {
	blocks := split_blocks(data, block_size)
	last_block := blocks[len(blocks)-1]
	unpaded := bytes.TrimRight(last_block, "\x04")

	return append(data[:len(data)-len(last_block)], unpaded...)
}

// Misc helpers
func assert_equal(exp, actual interface{}) {
	expVal := reflect.ValueOf(exp)
	if !expVal.IsValid() {
		panic("Please use assert.Nil instead.")
	}

	if !reflect.DeepEqual(exp, actual) {
		panic("Different")
	}

	fmt.Println("Success")
}

func lines_in_file(filename string) []string {
	data, _ := ioutil.ReadFile(filename)

	return strings.Split(string(data), "\n")
}

func abs(a float64) float64 {
	if a < 0 {
		return -a
	}
	return a
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}

	return b
}
