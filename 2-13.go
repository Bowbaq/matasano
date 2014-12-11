package main

import "strings"

func challenge_2_13() {
	key := random_bytes(16)
	encrypt := func(profile string) []byte {
		return ecb_encrypt([]byte(profile), key)
	}

	oracle := func(known []byte) []byte {
		return encrypt(profile_for(string(known)))
	}

	decrypt := func(encoded []byte) map[string]string {
		return parse(string(ecb_decrypt(encoded, key)))
	}

	// email=xxxxxxxxxx|admin&uid=10&rol|e=user
	//                 -- admin starts --
	// email=test@test.|com&uid=10&role=|user
	//                 -- = ends blk   --
	admin_block := oracle([]byte("xxxxxxxxxxadmin"))[16:32]
	ciphertext := append(oracle([]byte("test@test.com"))[:32], admin_block...)
	assert_equal("admin", decrypt(ciphertext)["role"])
}

func parse(encoded string) map[string]string {
	data := make(map[string]string)
	for _, pair := range strings.Split(encoded, "&") {
		i := strings.Index(pair, "=")
		if i > 0 {
			data[pair[:i]] = pair[i+1:]
		}
	}

	return data
}

func profile_for(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	return "email=" + email + "&uid=10&role=user"
}
