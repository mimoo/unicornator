package main

// TODO: for each checker, create an object with the regex to be initialized in an init(), the function itself, the severity, etc...
// then create an init that initialize all the regex

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

/*
 * If you add a checker/rule to this file:
 * you need to create the function AND add it to one of the checker map above
 * (e.g. if it's a check for C files, add it to the `checker_c` list)
 *
 * levels:
 *  - 1: informational
 *  - 2: warning
 *  - 3: important
 */

type checker struct {
	checker func(string) (string, string)
	level   int
}

var severity_str = map[int]string{
	1: "informational",
	2: "warning",
	3: "important",
}

//
// list of functions to use to check for pitfalls in files
//

// any files
var checker_list = []checker{
	checker{check_credentials_in_clear, 3},
	checker{check_misused_return_values_openssl, 3},
	checker{check_openssl_legacy, 3},
	checker{check_double_goto_fail, 3},
	checker{check_low_dh, 3},
	checker{check_return_values_openssl, 3},
	checker{check_common_pitfalls, 2},
	checker{check_deprecated_crypto_algo, 2},
	checker{check_password_hash_params, 2},
	checker{check_libgcrypt_mpi_invm, 2},
	checker{check_asserts, 1},
	checker{check_hex_string, 1},
	checker{check_key_iv_nonce_salt, 1},
	checker{check_double_negation, 1},
	checker{check_openssl_verify_final, 3},
	checker{check_RSA_public_exponent, 2},
}

// .go files
var checker_go = []checker{
	checker{check_go_err_shadowing, 3},
	checker{check_go_big_exp, 2},
	checker{check_go_math_rand, 2},
	checker{check_go_putvarint, 1},
}

// .erl, .hrl files
var checker_erlang = []checker{
	checker{check_erlang_random, 3},
	checker{check_erlang_recursion, 2},
}

// .rb
var checker_ruby = []checker{
	checker{check_ruby_rsa_encrypt, 3},
}

// .c, .cpp, .h, .hpp, .c.inc files
var checker_c = []checker{
	checker{check_int_sizet_cast_c, 3},
	checker{check_memcmp_hmac_c, 2},
	checker{check_common_pitfalls_c, 1},
	checker{check_cpp_unique_lock_mutex, 3},
}

// .java
var checker_java = []checker{
	checker{check_bouncy_castle, 3},
	checker{check_JKS_keystore, 3},
	checker{check_seeding_prng, 2},
	checker{check_3DES_wrap, 2},
	checker{check_GCM_param, 3},
}

// .ml
var checker_ocaml = []checker{
	checker{check_hashtbl_collision, 2},
}

//
// Checkers
//

/*
 * If you want to add a new checker function, the best thing
 * is to look at how another one is made.
 *
 * input:
 * - the line to analyze
 *
 * output on finding:
 * - the snippet to print
 * - the reason for tagging the snippet
 *
 */

// check for dh1024, dh512, ...
var check_low_dh_regex = regexp.MustCompile(`\bdh([0-9]{3,})`)

func check_low_dh(line string) (snippet, reason string) {

	// TODO: change the return value to finding, bool (with bool being true or false if something was found)
	/*
		type finding struct{
		description string,
		level int, // is this useful?
		snippet string
		}

		and here you could start defining in the beggining of the function:

		finding := finding{"Possible low Diffie-Hellman parameter"}

	*/

	if result := check_low_dh_regex.FindAllStringSubmatch(line, -1); len(result) != 0 {
		for _, found := range result {
			if bitlen, err := strconv.Atoi(found[1]); err == nil && bitlen < 2048 {
				snippet = line
				reason = "Possibe low Diffie-Hellman parameter"
				return
			}
		}
	}

	return
}

// check for C-type hexstrings (0xA4, 0xBF, ....)
var check_hex_string_regex = regexp.MustCompile(`(0x[A-Fa-f0-9]{1,2}\s*,\s*){3,}`)
var check_hex_string_regex2 = regexp.MustCompile(`(.*)=`)

func check_hex_string(line string) (string, string) {

	reason := "Hex array might be of cryptographic value."

	// match
	if check_hex_string_regex.MatchString(line) {
		// we already had a match?
		if _, ok := storage_string["hexstring"]; !ok {
			// append the previous line to have a nice start
			storage_string["hexstring"] = previous_line + "\n"
		}
		// append the line
		storage_string["hexstring"] += line + "\n"

	} else if _, ok := storage_string["hexstring"]; ok {
		// we don't have a match, but we just had one
		defer delete(storage_string, "hexstring")

		// check the name of the var?

		result := check_hex_string_regex2.FindStringSubmatch(storage_string["hexstring"])
		if result != nil {
			lowered := strings.ToLower(result[1])

			/*			if strings.Contains(lowered, "iv") {
							reason = "Could be a static IV/nonce."
			} else */
			if strings.Contains(lowered, "prime") {
				reason = "Should probably be a prime."
			}
		}

		// check the hexstring?
		//var hex_regex = regexp.MustCompile(`(0x[A-Fa-f0-9]{1,2})[\s\n]*,[\s\n]*)`)

		// return the previous match and the last line to have a nice end
		return storage_string["hexstring"] + line, reason
	}

	// this code will misbehave if the last line of a file triggers it

	// Probably here we should
	// reconstruct the hexstring
	// if it's longer than 40 characters, make it a bigInt
	// if it contains "prime", check if it's a prime
	// if it contains "DH", check if it's a safe prime
	// if it contains "RSA", check if it's large enough
	// etc...

	return "", ""
}

//
// OpenSSL
//

// checking for return values not used in OpenSSL
var openssl_func_return_val = []string{
	"EVP_DigestVerifyInit",
	"EVP_DigestVerifyUpdate",
	"RAND_bytes",
	"EVP_EncryptUpdate",
	"EVP_EncryptInit_ex",
	"EVP_EncryptFinal_ex",
	"EVP_DecryptInit_ex",
	"EVP_DecryptUpdate",
	"EVP_DecryptFinal_ex",
	"EVP_CipherInit_ex",
	"EVP_CipherUpdate",
	"EVP_CIPHER_CTX_cleanup",
	"EVP_CIPHER_param_to_asn1",
	"EVP_CIPHER_asn1_to_param",
}

func check_return_values_openssl(line string) (string, string) {

	reason := "Return value not verified"

	for _, item := range openssl_func_return_val {
		check_return_values_openssl_regex := regexp.MustCompile(`^[\t\s]*` + item + `.*`)
		if check_return_values_openssl_regex.MatchString(line) {
			return line, reason
		}

	}

	return "", ""

}

// checking for double negation
func check_double_negation(line string) (string, string) {
	reason := "Negating a boolean twice (`!!b`) is the same as writing `b`. This is either redundant, or a typo"

	if strings.Contains(line, "!!") {
		return line, reason
	}

	//
	return "", ""

}

// checking for credentials in clear
func check_credentials_in_clear(line string) (string, string) {
	reason := "AWS credentials in clear?"
	lowered := strings.ToLower(line)

	// AWS
	if strings.Contains(lowered, "aws_secret_access_key") && strings.Contains(lowered, "=") {
		return line, reason
	}

	//
	return "", ""

}

// checking for return values mis-used in OpenSSL
var check_misused_return_values_openssl_regex = regexp.MustCompile(`^.*![\t\s]*Rand_bytes`)
var check_misused_return_values_openssl_regex2 = regexp.MustCompile(`^[^=!]*[\s\t]*\b(\w+)[\s\t]*=[\t\s]*RAND_bytes`)
var check_misused_return_values_openssl_regex3 = regexp.MustCompile(`^[^!]*![\s\t]*` + storage_string["RAND_bytes_var"] + ``)

func check_misused_return_values_openssl(line string) (string, string) {

	// if(!RAND_bytes)
	reason := "RAND_bytes should be checked to be 1. Here a -1 return value might trip this"

	if check_misused_return_values_openssl_regex.MatchString(line) {
		return line, reason
	}

	// res = RAND_bytes; !res

	res := check_misused_return_values_openssl_regex2.FindStringSubmatch(line)

	if len(res) == 2 {
		storage_int["RAND_bytes"] = 1
		storage_string["RAND_bytes"] = previous_line + "\n"
		storage_string["RAND_bytes_var"] = res[1]
	}

	if storage_int["RAND_bytes"] > 0 {

		if storage_int["RAND_bytes"] > 3 {
			storage_int["RAND_bytes"] = 0
			storage_string["RAND_bytes"] = ""
		} else {
			storage_string["RAND_bytes"] += line + "\n"
			storage_int["RAND_bytes"]++

			if check_misused_return_values_openssl_regex3.MatchString(line) {

				storage_int["RAND_bytes"] = 0
				defer delete(storage_string, "RAND_bytes")
				delete(storage_string, "RAND_bytes_var")

				return storage_string["RAND_bytes"], reason
			}
		}
	}

	return "", ""
}

// legacy/deprecated OpenSSL functions
var legacy_openssl_funcs = map[string]string{
	"X509_NAME_oneline": "Legacy function, should not use.",
	"X509_NAME_print":   "Legacy function, should not use.",
	"SSL_set_bio":       "Legacy function, should not use.",
	"ASN1_STRING_print": "Legacy function, should not use.",
	"RAND_pseudo_bytes": "Deprecated function, see https://jbp.io/2014/01/16/openssl-rand-api/",
}

func check_openssl_legacy(line string) (string, string) {

	for name, reason := range legacy_openssl_funcs {
		if strings.Contains(line, name) {
			return line, reason
		}
	}

	return "", ""
}

//
// Java
//

// check for java Bouncy Castle pitfalls
var unwanted_bouncy_castle = []string{
	"DES/", // DES/ECB, DES/CBC
	"RSA/ECB/PKCS1Padding",
	"getInstance(\"DES\")",
	"AES/ECB",
}

func check_bouncy_castle(line string) (string, string) {

	reason := "Does not follow best practice."

	for _, item := range unwanted_bouncy_castle {
		if strings.Contains(line, item) {
			return line, reason
		}
	}

	return "", ""
}

func check_seeding_prng(line string) (string, string) {

	reason := "Should not manually seed a PRNG."

	if strings.Contains(line, "generateSeed") || strings.Contains(line, "setSeed") {
		return line, reason
	}

	return "", ""
}

func check_3DES_wrap(line string) (string, string) {

	reason := "3DES Wrap is a shady algorithm. Not approved by the NIST.\n"
	reason += "see http://web.cs.ucdavis.edu/~rogaway/papers/keywrap.html"

	if strings.Contains(line, "DESede.Wrap") {
		return line, reason
	}

	return "", ""
}

func check_GCM_param(line string) (string, string) {

	reason := "GCMParameterSpec takes a length in bits, not in bytes\n"
	reason += "https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/GCMParameterSpec.html"

	var check_hex_string_regex = regexp.MustCompile(`GCMParameterSpec\s*\(\s*12`)

	// match
	if check_hex_string_regex.MatchString(line) {
		return line, reason
	}

	return "", ""
}

// JKS Keystore
func check_JKS_keystore(line string) (string, string) {
	reason := "The JKS keystore is outdated, it might be replaced with JCEKS\n"
	reason += " see https://github.com/floyd-fuh/JKS-private-key-cracker-hashcat\n"
	reason += " or https://cryptosense.com/cracking-java-keystores-with-hashcat"

	if strings.Contains(line, "java.security.KeyStore") {
		return line, reason
	} else {
		return "", ""
	}
}

//
//
//

// insecure parameters for pkbdf2 or bcrypt
var check_password_hash_params_regex = regexp.MustCompile(`\b([0-9]+)\b`)

func check_password_hash_params(line string) (string, string) {

	if strings.Contains(line, "pbkdf") {

		if result := check_password_hash_params_regex.FindStringSubmatch(line); result != nil {
			if iteration, err := strconv.Atoi(result[1]); err == nil && iteration < 50000 {
				return line, "Use of low iteration number for PKBDF"
			}
		}

	}

	return "", ""

}

// common pitfalls
var kins = regexp.MustCompile(`(?i)^[^=(]*\biv\b[^=]*=[^=]`)
var kins2 = regexp.MustCompile(`(?i)^[^=(]*\bnonce\b[^=]*=[^=]`)
var kins3 = regexp.MustCompile(`(?i)^[^=(]*\bsalt\b[^=]*=[^=]`)
var kins4 = regexp.MustCompile(`(?i)^[^=(]*\bkey\b[^=]*=[^=]`) // TODO: Problem with this one is that "key" is used a lot in non-crypto contexts

func check_key_iv_nonce_salt(line string) (string, string) {

	// static IV/nonce/salt?

	if !strings.Contains(line, "NULL") && (!strings.Contains(line, "new") && (kins.MatchString(line) || kins2.MatchString(line) || kins3.MatchString(line) || kins4.MatchString(line))) {

		if strings.Contains(line, "{") || strings.Contains(line, "getbytes") || strings.Contains(line, "default") {
			return line, "Could be a static IV/nonce/salt/key."
		} else {
			return line, "IV/nonce/salt/key being declared, make sure it is not static."
		}
	}

	//
	return "", ""
}

// common pitfalls
func check_asserts(line string) (string, string) {

	reason := "Make sure that 'assert' is not used in production: you do not a way to crash the server."

	lowered := strings.ToLower(line)

	if strings.Contains(lowered, "assert") {
		return line, reason
	}

	//
	return "", ""
}

// check_common_pitfalls
var check_common_pitfalls_regex = regexp.MustCompile(`(?i)rand.*=.*time`)
var check_common_pitfalls_regex2 = regexp.MustCompile(`(?i)seed.*=.*time`)
var check_common_pitfalls_regex3 = regexp.MustCompile(`(?i)\bsha[^=]*\(.*pass`)

func check_common_pitfalls(line string) (string, string) {

	// random with time?
	if check_common_pitfalls_regex.MatchString(line) {
		return line, "random value using the time?"
	}

	// seeding with time?

	if check_common_pitfalls_regex2.MatchString(line) {
		return line, "seeding a PRNG using the time?"
	}

	// hashing a password

	if check_common_pitfalls_regex3.MatchString(line) {
		return line, "hashing a password?"
	}

	// using a password when expecting a key
	var regex = regexp.MustCompile(`(?i)\bkey[^=]*=.*pass`)
	if regex.MatchString(line) {
		return line, "using a password instead of a key?"
	}

	// IV same as key
	regex = regexp.MustCompile(`(?i)\biv\b[^=]*=.*\bkey\b`)
	if regex.MatchString(line) {
		return line, "IV is same as key?"
	}

	// ECB?
	regex = regexp.MustCompile(`(?i)\becb\b`)

	if regex.MatchString(line) {
		return line, "Make sure this is using not the insecure ECB mode."
	}

	//
	return "", ""
}

// common pitfalls
var deprecated_crypto_algo = map[string]string{
	"md2":      "MD2 should be replaced by SHA-3 (or if not available, SHA-256/512).",
	"md4":      "MD4 should be replaced by SHA-3 (or if not available, SHA-256/512).",
	"md5":      "MD5 should be replaced by SHA-3 (or if not available, SHA-256/512).",
	"sha1":     "SHA-1 should be replaced by SHA-3 (or if not available, SHA-256/512).",
	"rc2":      "RC2 is insecure",
	"rc4":      "RC4 is insecure",
	"mersenne": "Merssene Twister is not a cryptographically secure pseudo-random number generator.",
	"mt19937":  "Merssene Twister (mt19937) is not a cryptographically secure pseudo-random number generator.",
	"ecb":      "ECB mode should not be used (insecure).",
	"3des":     "3DES should be replaced by AES-GCM.",
	"getpid":   "getpid is not a secure way to generate random numbers",
	"srand":    "srand is not a secure way to generate random numbers",
	"oee":      "",
	"crc":      "crc is not a secure hash function, make sure it is not used as such",
	"rot13":    "rot13 is not a secure way to do crypto stuff, make sure it is not used as such",
	"ssl3":     "SSL3 should not be used because of POODLE",
}

func check_deprecated_crypto_algo(line string) (string, string) {

	for key, reason := range deprecated_crypto_algo {
		regex := regexp.MustCompile(`(?i)\b` + key + `\b`)

		if regex.MatchString(line) {
			return line, reason
		}

	}

	//
	return "", ""
}

func check_libgcrypt_mpi_invm(line string) (string, string) {

	reason := "The gcry_mpi_invm function from libgcrypt will return 1 as the inverse of 0 for any group.\n"
	reason += "from: https://www.gnupg.org/documentation/manuals/gcrypt/Calculations.html#Calculations\n"
	reason += "> Function: int gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m)\n"
	reason += "> Set x to the multiplicative inverse of a \bmod m. Return true if the inverse exists.\n"
	reason += "Check if an attacker could give it 0\n"

	if strings.Contains(line, "gcry_mpi_invm") {
		return line, reason
	}

	return "", ""
}

//
// C specific functions
//

// common pitfalls
func check_common_pitfalls_c(line string) (string, string) {

	// static IV/nonce/salt?
	regex := regexp.MustCompile(`(?i)^[\t\s]*#define.*\biv\b`)
	regex2 := regexp.MustCompile(`(?i)^[\t\s]*#define.*\bnonce\b`)
	regex3 := regexp.MustCompile(`(?i)^[\t\s]*#define.*\bsalt\b`)
	regex4 := regexp.MustCompile(`(?i)^[\t\s]*#define.*\bkey\b`)
	//regex5 := regexp.MustCompile(`(?i)^[\t\s]*#define.*\bprivate\b`)

	if !strings.Contains(line, "new") && (regex.MatchString(line) || regex2.MatchString(line) || regex3.MatchString(line) || regex4.MatchString(line)) {
		if strings.Contains(line, "{") || strings.Contains(line, "getbytes") || strings.Contains(line, "default") {
			return line, "Could be a static IV/nonce/salt/key."
		} else {
			return line, "IV/nonce/salt/key being declared, make sure it is not static."
		}

	}

	// random with time?
	regex = regexp.MustCompile(`(?i)rand.*=.*time`)
	if regex.MatchString(line) {
		return line, "random value using the time?"
	}

	//
	return "", ""
}

// int something = size_t other thing
func check_int_sizet_cast_c(line string) (string, string) {

	//
	regex := regexp.MustCompile(`(?i)^[\t\s]*int[\t\s\w]+=[\s\t]*strlen[\s]*\(`)

	if regex.MatchString(line) {
		return line, "the returned value is a size_t value, not an int."
	}

	//
	return "", ""
}

func check_memcmp_hmac_c(line string) (string, string) {
	//
	regex := regexp.MustCompile(`(?i)\bmemcmp[\s]*\([\w\s\t,]*mac\b`)

	if regex.MatchString(line) {
		return line, "Non-constant time comparison of a Message Authentication Code tag."
	}

	//
	return "", ""
}

//
//
//

// double go to fail :D (apple)
func check_double_goto_fail(line string) (string, string) {

	reason := "Double goto fail?"

	// match
	regex := regexp.MustCompile(`^[\t\s]*goto`)

	if regex.MatchString(line) {
		// we already had a match
		if _, ok := storage_bool["doublegoto"]; ok {
			delete(storage_bool, "doublegoto")
			return previous_line + "\n" + line, reason
		} else {
			storage_bool["doublegoto"] = true
		}

	} else if _, ok := storage_bool["doublegoto"]; ok {
		// we don't have a match, but we just had one
		delete(storage_bool, "doublegoto")
	}

	return "", ""
}

// OpenSSL
func check_openssl_verify_final(line string) (string, string) {

	reason := "Unlike most functions, OpenSSL's EV_VerifyFinal can return negative values on error\n"
	reason += "Unless we're dealing with BoringSSL, which corrected the issue and always returns 0 on error\n"
	reason += "Check https://underhandedcrypto.com/2018/02/25/joseph-birr-pixtons-2017-entry-poor-api-design-in-openssl/\n"
	reason += "and CVE-2008-5077"

	regex := regexp.MustCompile(`if\s*\(\s*EVP_VerifyFinal\s*\(`)

	if regex.MatchString(line) {
		return line, reason
	} else {
		return "", ""
	}
}

// OpenSSL
func check_RSA_public_exponent(line string) (string, string) {

	reason := "A common RSA public exponent is 65537\n"
	reason += "it is sometimes miswritten, and probably insecure."

	regex := regexp.MustCompile(`\b[65537]{5}\b`)

	if regex.MatchString(line) && !strings.Contains(line, "65537") && !strings.Contains(line, "65535") {
		return line, reason
	} else {
		return "", ""
	}
}

//
// GoLang
//

// Golang big.Exp
/*
	{
		name: "go big Exp",
		reason: "...",
		contains: [".Exp("],
		not_contains: ["nil)"],
		test_must_catch: [".Exp(x, a, 0)", ".Exp(b, c, d)"],
		test_must_not_catch: [".Exp(smthg, e, nil)"],
	}

*/
func check_go_big_exp(line string) (string, string) {

	reason := "If big.Exp is used, make sure the third argument cannot be zero\n"
	reason += "Check CVE-2016-3959 for more details: https://www.cryptologie.net/article/347/"

	if strings.Contains(line, ".Exp(") && !strings.Contains(line, "nil)") {
		return line, reason
	} else {
		return "", ""
	}
}

// Golang tls.KeyLogWriter
func check_go_tls_keyLogWriter(line string) (string, string) {
	reason := "If tls.KeyLogWriter is used, make sure it is only used for debugging.\n"
	reason += "As the documentation states: \"Use of KeyLogWriter compromises security and should only be used for debugging.\""

	if strings.Contains(line, "KeyLogWriter") {
		return line, reason
	} else {
		return "", ""
	}
}

// Golang big.Sqrt
func check_go_putvarint(line string) (string, string) {
	reason := "If binary's PutUvarint/PutVarint/ReadVarint/ReadUvarint/... are used, make sure that they indeed encode to/from 'variable' integers"

	if strings.Contains(line, "Uvarint") || strings.Contains(line, "Varint") {
		return line, reason
	} else {
		return "", ""
	}
}

// Golang math/rand
func check_go_math_rand(line string) (string, string) {
	reason := "math/rand generates bad randomness for crytpo."
	if strings.Contains(line, "math/rand") {
		return line, reason
	} else {
		return "", ""
	}
}

// err shadowing
// note: Go include a go file parser: https://golang.org/pkg/go/parser/
// this is kind of a useless function, you can do go tool vet --shadow . instead
func check_go_err_shadowing(line string) (string, string) {

	reason := "The error variable '%s' is being re-declared (shadow)."

	// we are already in such a function
	if shadow, ok := storage_string["go_err_shadowing"]; ok {

		// line
		storage_string["go_err_shadowing_line"] += line + "\n"

		// test
		regex := regexp.MustCompile(`\b` + shadow + `\b[,\s\t\w]*:=`)
		if regex.MatchString(line) {
			delete(storage_string, "go_err_shadowing")
			delete(storage_int, "go_err_shadowing")
			defer delete(storage_string, "go_err_shadowing_line")
			return storage_string["go_err_shadowing_line"], fmt.Sprintf(reason, shadow)
		}

		// are we out?
		storage_int["go_err_shadowing"] += strings.Count(line, "{") - strings.Count(line, "}")
		if storage_int["go_err_shadowing"] <= 0 {
			delete(storage_string, "go_err_shadowing")
			delete(storage_int, "go_err_shadowing")
			delete(storage_string, "go_err_shadowing_line")
		}
	} else {
		// are we entering a function with a declared `something` of
		// type error in the output?
		// ex: func my_function() (err error) {
		regex := regexp.MustCompile(`\bfunc\b[^)]*\)[^{]*\b([\w]+)\b[\s\t]*\berror\b`)
		if result := regex.FindStringSubmatch(line); len(result) > 1 {
			// how many { ?
			braces := strings.Count(line, "{") - strings.Count(line, "}")

			// are we not out of the function already?
			if braces > 0 {
				storage_string["go_err_shadowing"] = result[1]
				storage_int["go_err_shadowing"] = braces
				storage_string["go_err_shadowing_line"] = line + "\n"
			}

		}
	}

	//
	return "", ""
}

//
// Erlang
//

func check_erlang_random(line string) (string, string) {

	reason := "use crypto:rand_bytes instead"

	if strings.Contains(line, "random:seed(") {
		return line, reason
	} else {
		return "", ""
	}
}

func check_erlang_recursion(line string) (string, string) {

	reason := "careful of infinite loops implemented as recursions inside of a try-catch block\n"
	reason += "https://stackoverflow.com/questions/17559946/no-tail-recursive-code-in-a-try-catch-block\n"
	reason += "https://stackoverflow.com/questions/27028824/erlang-stackoverflow-with-recursive-function-that-is-not-tail-call-optimized\n"
	reason += "the stack being implemented on the heap with Erlang, this can lead to the Erlang process to crash\n"
	reason += "which could be fine if it is monitored and is restarted with a supervisor (but state could be lost?)\n"
	reason += "worse, it could lead to a VM crash\n"
	reason += "https://stackoverflow.com/questions/11112261/how-is-running-out-of-memory-handled-in-erlang\n"
	reason += "you can confirm this issue by adding io:format(\"~p~n\", [erlang:process_info(self())]),\n"
	reason += "and observe the stack growing."

	regex := regexp.MustCompile(`try\s*\(\s*receive`)

	if regex.MatchString(line) {
		return line, reason
	} else {
		return "", ""
	}
}

//
// Ruby
//

func check_ruby_rsa_encrypt(line string) (string, string) {

	reason := "This uses RSA PKCS #1 v1.5 padding for encryption\n"
	reason += "Don't do that dude\n"
	reason += "Use RSA PKCS #1 v2.0 (OAEP) instead\n"
	reason += "like that: public_encrypt(., 4)\n"
	reason += "or private_decrypt(., 4)\n"

	regex1 := regexp.MustCompile(`\w\.public_encrypt\([^),]+\)`)
	regex2 := regexp.MustCompile(`\w\.private_decrypt\([^),]+\)`)
	if regex1.MatchString(line) || regex2.MatchString(line) {
		return line, reason
	} else {
		return "", ""
	}
}

//
// C++
//

func check_cpp_unique_lock_mutex(line string) (string, string) {

	reason := "unique_lock<mutex>(something); is the same as\n"
	reason += "unique_lock<mutex> something;\n"
	reason += "hence a unique_lock gets declared but does not get used\n"
	reason += "see bug 5 from https://www.youtube.com/watch?v=3MB2iiCkGxg"

	regex := regexp.MustCompile(`\bunique_lock<(std::)*mutex>[^(]*\(\w*\);`)
	if regex.MatchString(line) {
		return line, reason
	} else {
		return "", ""
	}
}

//
// Ocaml
//

func check_hashtbl_collision(line string) (string, string) {

	reason := "Hashtbl.create is by default not using a keyed hash function\n"
	reason += "unless it uses the optional parameter ~random:true\n"
	reason += "This can be a problem if keys are untrusted user input.\n"
	reason += "cf https://lwn.net/Articles/574761/\n"
	reason += "and https://github.com/lucasaiu/ocaml/blob/master/stdlib/hashtbl.mli#L48"

	if strings.Contains(line, "Hashtbl.create") && !strings.Contains(line, "~random:true") {
		return line, reason
	} else {
		return "", ""
	}
}
