package main

import (
	"fmt"
	"io/ioutil"
	"sort"
)

type candidate struct {
	key_size int
	dist     float64
}

func (c candidate) String() string {
	return fmt.Sprintf("key size %d -> %f\n", c.key_size, c.dist)
}

type ByDist []candidate

func (a ByDist) Len() int           { return len(a) }
func (a ByDist) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByDist) Less(i, j int) bool { return a[i].dist < a[j].dist }

func challenge_1_6() {

	data := from_base64_file("inputs/1-6.txt")

	// Find candidate key sizes
	var candidates []candidate
	for ks := 2; ks <= 40; ks++ {
		dist := avg_hamming_distance(data[0:ks], data[ks:ks*2], data[ks*2:ks*3], data[ks*3:ks*4])
		candidates = append(candidates, candidate{ks, float64(dist) / float64(ks)})
	}

	sort.Sort(ByDist(candidates))

	// Test candidate key sizes
	var (
		best_key   string
		best_score int
	)

	for _, c := range candidates[0:5] {
		var guessed_key string
		for _, block := range transpose(split_blocks(data, c.key_size)) {
			_, c, _ := find_single_char_xor(block)
			guessed_key += string(c)
		}
		decoded := string(xor_repeat(data, guessed_key))
		score := english_score(decoded)
		if score > best_score {
			best_score = score
			best_key = guessed_key
		}
	}

	output, _ := ioutil.ReadFile("outputs/1-6.txt")
	assert_equal(output, xor_repeat(data, best_key))
}
