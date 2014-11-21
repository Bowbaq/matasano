package main

import (
	"crypto/rand"
	"io"
	mrand "math/rand"
	"time"
)

func challenge_2_11() {
	mrand.Seed(time.Now().UnixNano())
	for i := 0; i < 25; i++ {
		alg, ciphertext := random_encrypt([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"))
		ecb := is_ecb(ciphertext)
		if (ecb && alg != "ecb") || (!ecb && alg == "ecb") {
			panic("weird")
		}
	}
}

func random_bytes(n int) []byte {
	k := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

func random_encrypt(data []byte) (string, []byte) {
	key := random_bytes(16)

	prefix := random_bytes(mrand.Intn(5) + 5)
	suffix := random_bytes(mrand.Intn(5) + 5)
	data = append(prefix, append(data, suffix...)...)

	if mrand.Intn(2) == 0 {
		iv := random_bytes(16)
		return "cbc", cbc_encrypt(data, key, iv)
	} else {
		return "ecb", ecb_encrypt(data, key)
	}
}
