package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

var challenges_names = []string{"1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14"}
var challenges = map[string]func(){
	"1.1":  challenge_1_1,
	"1.2":  challenge_1_2,
	"1.3":  challenge_1_3,
	"1.4":  challenge_1_4,
	"1.5":  challenge_1_5,
	"1.6":  challenge_1_6,
	"1.7":  challenge_1_7,
	"1.8":  challenge_1_8,
	"2.9":  challenge_2_9,
	"2.10": challenge_2_10,
	"2.11": challenge_2_11,
	"2.12": challenge_2_12,
	"2.13": challenge_2_13,
	"2.14": challenge_2_14,
}

func main() {
	if len(os.Args) > 1 {
		log.Printf("Challenge %s ==>\n", os.Args[1])
		challenges[os.Args[1]]()
	} else {
		for _, name := range challenges_names {
			log.Printf("Challenge %s ==>\n", name)
			challenges[name]()
		}
	}
}

func challenge_1_1() {
	assert_equal(
		"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		to_base64(from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")),
	)
}

func challenge_1_2() {
	assert_equal(
		to_hex(xor(from_hex("1c0111001f010100061a024b53535009181c"), from_hex("686974207468652062756c6c277320657965"))),
		"746865206b696420646f6e277420706c6179",
	)
}

func challenge_1_3() {
	decoded, _, _ := find_single_char_xor(from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

	assert_equal(decoded, "Cooking MC's like a pound of bacon")
	fmt.Println("Success")
}

func challenge_1_4() {
	var (
		best_guess string
		best_score int
	)

	for _, line := range lines_in_file("inputs/1-4.txt") {
		guess, _, score := find_single_char_xor(from_hex(line))
		if score > best_score {
			best_score = score
			best_guess = guess
		}
	}

	assert_equal("Now that the party is jumping\n", best_guess)
	fmt.Println("Success")
}

func challenge_1_5() {
	const key = `ICE`
	const expected = `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`
	const input = `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	assert_equal(expected, to_hex(xor_repeat([]byte(input), key)))
}

// See 1-6.go

func challenge_1_7() {
	key := []byte("YELLOW SUBMARINE")
	ciphertext := from_base64_file("inputs/1-7.txt")
	output, _ := ioutil.ReadFile("outputs/1-7.txt")

	assert_equal(output, ecb_decrypt(ciphertext, key))
}

func challenge_1_8() {
	for l, line := range lines_in_file("inputs/1-8.txt") {
		if is_ecb(from_base64(line)) {
			fmt.Println("Line", l, "is ECB encoded")
			return
		}
	}
}

func challenge_2_9() {
	assert_equal("YELLOW SUBMARINE\x04\x04\x04\x04", string(pcks_pad([]byte("YELLOW SUBMARINE"), 20)))
}

func challenge_2_10() {
	ciphertext := from_base64_file("inputs/2-10.txt")
	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{0}, 16)

	output, _ := ioutil.ReadFile("outputs/2-10.txt")
	assert_equal(output, cbc_decrypt(ciphertext, key, iv))

	plaintext := []byte("The lazy fox")
	assert_equal(plaintext, cbc_decrypt(cbc_encrypt(plaintext, key, iv), key, iv))
}

// See 2-11.go

// See 2-12.go

// See 2-13.go
