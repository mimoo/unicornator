package main

import(
	"os"
	"bufio"
	"strings"
)

var keywords = []string{
	"aes128",
	"aes256",
	"argon2",
	"asn",
	"blum",
	"blowfish",
	"cert",
	"crypt", // includes encrypt/decrypt/bcrypt/scrypt
	"curve",
	"derive",
	"diffie-hellman",
	"dsa",
	"elgamal",
	"elliptic",
	"fortuna",
	"hsm",
	"keccak",
	"lfsr",
	"md5",
	"md4",
	"md2",
	"password",
	"pbkdf",
	"pseudo",
	"rand", // random
	"ripemd",
	"rc4",
	"rfc",
	"rsa",
	"seed",
	"shamir",
	"sha1",
	"sha2",
	"sha3",
	"sha-1",
	"sha-2",
	"sha-3", // SHA-384
	"sha-5", // sha-512
	"shake",
	"signature",
	"ssl", // includes OpenSSL
	"tls",
	"twofish",
	"mac", //  includes hmac
	"yarrow",
	"whirlpool",
	"25519",
}

func crypto_ranking(path string) int {

	// Open file
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	// init
	score := 0
	
	// file is read line by line
	line_number = 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		for _, keyword := range keywords {
			if strings.Contains(line, keyword) {
				score += 1
			}
		}
	}

	//
	return score
}
