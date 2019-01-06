package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//
// global vars
//

const (
	version       = "0.1"
	LINE_TOO_LONG = 250
)

// files
var MAX_FILE_SIZE int64 = 50000000 // 50 mb
var ignored_files []ignored

type ignored struct {
	file   string
	reason string
}

// file parser
var line_number int                  // line number
var previous_line string             // stores the previous line
var storage_string map[string]string // storage helper
var storage_bool map[string]bool     // storage helper
var storage_int map[string]int       // storage helper

// level of severity (1 to 3)
var level *int
var html *bool
var no_ignored *bool
var ranking *bool

// final rank if ranking files
var final_rank map[int][]string

//
// Core Functions
//

// test is a file is a binary file
func isBinary(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	// read the first 2000 bytes
	buf := make([]byte, 2000)
	n, _ := io.ReadFull(file, buf) // don't care about an error

	// test if there is a 0 byte
	if idx := bytes.IndexByte(buf[:n], 0); idx != -1 {
		return true
	}

	return false

	/*
		if utf8.Valid(buf) {
			return false
		} else {
			return true
		}
	*/
}

// Check if a line looks like an array entry
// ex: `"this is array entry",`
func isArrayEntry(line, extension string) bool {

	if extension == ".go" {
		return false
	}

	regex := regexp.MustCompile(`^[\s\t]*".*",*$`)

	// we detected the end of the comment
	return regex.MatchString(line)
}

// check if a line is a comment, or starts a comment
// or ends a comment
var isCommentRegex = map[string]string{
	"//":   `^[\t\s]*\/\/`,
	"#":    `^[\t\s]*#`,
	"/*":   `^[\s\t]*\/\*`,
	"*/":   `\*\/[\s\t]*$`,
	"/**/": `^[\s\t]*\/\*.*\*\/[\s\t]*$`,
	`"""`:  `^[\s\t]*"""`,
}

func isComment(line string, extension string) bool {

	var regex *regexp.Regexp

	// `/*`
	if _, ok := storage_bool["/*"]; ok {
		// we're already inside a multi-line comment
		regex = regexp.MustCompile(isCommentRegex["*/"])
		// we detected the end of the comment
		if regex.MatchString(line) {
			defer delete(storage_bool, "/*")
		}

		return true

	} else {
		// we detected the start and end of a multi-line comment
		regex = regexp.MustCompile(isCommentRegex["/**/"])
		if regex.MatchString(line) {
			return true
		}
		// we detected the start of a multi-line comment
		regex = regexp.MustCompile(isCommentRegex["/*"])
		if regex.MatchString(line) {
			// nested /*
			storage_bool["/*"] = true
			return true
		}
	}

	// for python
	if extension == ".py" || extension == ".sage" {

		// """
		if _, ok := storage_bool[`"""`]; ok {
			// we're already inside a multi-line comment
			regex = regexp.MustCompile(isCommentRegex[`"""`])
			// we detected the end of the comment
			if regex.MatchString(line) {
				defer delete(storage_bool, `"""`)
			}

			return true

		} else {
			// we detected the start of a multi-line comment
			regex = regexp.MustCompile(isCommentRegex[`"""`])
			if regex.MatchString(line) {
				// nested /*
				storage_bool[`"""`] = true
				return true
			}
		}

		// #
		regex = regexp.MustCompile(isCommentRegex["#"])
		if regex.MatchString(line) {
			return true
		}
	}

	// `//`
	regex = regexp.MustCompile(isCommentRegex["//"])
	return regex.MatchString(line)
}

// parse a file for weaknesses
func parse_file(path string, extension string) {

	// Open file
	file, err := os.Open(path)
	if err != nil {
		ignored_files = append(ignored_files, ignored{path, "couldn't open file"})
		return
	}
	defer file.Close()

	// init of useful storage for check functions
	// (see `check_hexstring()` for an example)
	storage_string = make(map[string]string)
	storage_bool = make(map[string]bool)
	storage_int = make(map[string]int)

	// file is read line by line
	line_number = 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line_number++

		// is weird binary stuff in here?
		// note: this might really slow down... so commented for now
		/*
			if !utf8.Valid([]byte(line)) {
				ignored_files = append(ignored_files, ignored{path, "binary file"})
				return
			}
		*/

		// ignore line if it's a comment
		if isComment(line, extension) {
			continue
		}

		// ignore line if it's an array entry
		if isArrayEntry(line, extension) {
			continue
		}

		if len(line) > LINE_TOO_LONG {
			continue
		}

		//
		// EXTENSION-SPECIFIC CHECKS
		//
		var check_temp *[]checker = nil

		if extension == ".go" {
			check_temp = &checker_go
		} else if extension == ".c" || extension == ".h" || extension == ".cpp" || extension == ".hpp" || extension == ".c.inc" || extension == ".cpp" {
			check_temp = &checker_c
		} else if extension == ".java" {
			check_temp = &checker_java
		} else if extension == ".erl" || extension == ".hrl" {
			check_temp = &checker_erlang
		} else if extension == ".rb" {
			check_temp = &checker_ruby
		} else if extension == ".ml" {
			check_temp = &checker_ocaml
		}

		if check_temp != nil {
			for _, checker := range *check_temp {

				if checker.level < *level {
					continue
				}

				if result, reason := checker.checker(line); result != "" {
					fmt.Printf("\n%s line %d:\n", path, line_number)
					fmt.Println(" - severity:", severity_str[checker.level])
					if reason != "" {
						fmt.Println(" - reason:", reason, "\n")
					} else {
						fmt.Println("")
					}
					fmt.Println(result)
					fmt.Println("\n----------------------")

				}
			}
		}

		//
		// COMMON CHECKS
		//

		for _, checker := range checker_list {

			if checker.level < *level {
				continue
			}

			if result, reason := checker.checker(line); result != "" {
				fmt.Printf("\n%s line %d:\n", path, line_number)
				fmt.Println(" - severity:", severity_str[checker.level])
				if reason != "" {
					fmt.Println(" - reason:", reason, "\n")
				} else {
					fmt.Println("")
				}
				fmt.Println(result)
				fmt.Println("\n----------------------")

			}
		}

		// END
		previous_line = line
	}

	// error?
	if err := scanner.Err(); err != nil {
		ignored_files = append(ignored_files, ignored{path, "error while reading file"})
		return
	}

	//
	return
}

// TODO: detect if the file is a PEM file without the extension
func detect_file_type(path string) string {
	return ""
}

// Parse .pem files
func parse_pem_file(path string) bool {

	//fmt.Println("parsing PEM file")
	fmt.Println("\n" + path + ":\n")
	// get content
	pem_bytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(" - error parsing the PEM file")
		return false
	}

	pem_content := string(pem_bytes)

	// PEM -> DER
	der_content, _ := pem.Decode([]byte(pem_content))
	if der_content == nil {
		fmt.Println(" - can't parse the pem file")
		return false
	}

	// what kind of PEM file?
	if strings.Contains(pem_content, "SSL SESSION PARAMETERS") {
		fmt.Println(" - detected: ssl session parameters")
	} else if strings.Contains(pem_content, "CERTIFICATE REQUEST") {
		fmt.Println(" - detected: certificate request")
	} else if strings.Contains(pem_content, "RSA PRIVATE KEY") {
		fmt.Println(" - detected: rsa private key")
		if x509.IsEncryptedPEMBlock(der_content) {
			fmt.Println(" - pem file is encrypted")
			return false
		} else {
			fmt.Println(" x private key in clear")
		}

	} else if strings.Contains(pem_content, "PKCS7") {

		fmt.Println("detected: pkcs7")
	} else if strings.Contains(pem_content, "EC PRIVATE KEY") {

		fmt.Println("detected: ec private key")
		if x509.IsEncryptedPEMBlock(der_content) {
			fmt.Println(" - pem file is encrypted")
			return false
		} else {
			fmt.Println(" x private key in clear")
		}

	} else if strings.Contains(pem_content, "DSA PARAMETERS") {

		fmt.Println("detected: dsa parameters")
	} else if strings.Contains(pem_content, "DH PARAMETERS") {

		fmt.Println("detected: dh parameters")
	} else if strings.Contains(pem_content, "DSA PRIVATE KEY") {

		fmt.Println("detected: dsa private key")
		if x509.IsEncryptedPEMBlock(der_content) {
			fmt.Println(" - pem file is encrypted")
			return false
		} else {
			fmt.Println(" x private key in clear")
		}

	} else if strings.Contains(pem_content, "X509 CRL") {

		fmt.Println("detected: x509 crl")
	} else if strings.Contains(pem_content, "SERVERINFO FOR CT") {
		fmt.Println("\n", path, "detected: serverinfo for ct")
	} else if strings.Contains(pem_content, "SERVERINFO FOR TACK") {

		fmt.Println("detected: serverinfo for tack")

		// defaults
	} else if strings.Contains(pem_content, "PRIVATE KEY") {

		fmt.Println(" - detected: private key")

		if x509.IsEncryptedPEMBlock(der_content) {
			fmt.Println(" - pem file is encrypted")
			return false
		} else {
			fmt.Println(" x private key in clear")
			fmt.Println(" - pem does not advertise what type of key it is")
		}
	} else if strings.Contains(pem_content, "CERTIFICATE") {

		fmt.Println(" - detected: certificate")

		check_certificate(der_content.Bytes)

	} else if strings.Contains(pem_content, "PUBLIC KEY") {

		fmt.Println(" - detected: public key")

		check_pem_public_key(der_content)

		// can't parse
	} else {

		fmt.Println(" - can't detect PEM file, please contact the author of this tool")

		// log
		fmt.Println("\nPEMFILE:\n", pem_content)
	}

	//
	return false
}

// parse certificate files (.crt)
func parse_crt_file(path string) bool {

	//
	fmt.Println("\n", path, ":\n")

	// get content
	der_bytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(" - error parsing the certificate file")
		return false
	}

	// parse cert
	check_certificate(der_bytes)

	return false
}

// parse .der files (keys, certs, ...)
func parse_der_file(path string) bool {

	// check the name, does it contain "private key" or "certificate" or something?

	// check the asn.1 structure, does it look like something we know?

	// let's try to parse them like .crt files at the moment
	parse_crt_file(path)

	return false
}

// main function called when visiting a file or directory
func visit(path string, f os.FileInfo, err error) error {

	// debug
	if false {
		fmt.Println("Visited: ", path)
		fmt.Println("  - name: ", f.Name())
		fmt.Println("  - size: ", f.Size())
		fmt.Println("  - mode: ", f.Mode())
		fmt.Println("  - sys: ", f.Sys())
	}

	// ignore directories
	if f.IsDir() || path == "." {
		return nil
	}

	// ignore specific path
	for _, item := range unwanted_paths {
		if strings.Contains(path, item) {
			//fmt.Println("ignored because", item)
			ignored_files = append(ignored_files, ignored{path, "Unwanted path"})
			return nil
		}
	}

	// ignore empty/large files
	if size := f.Size(); size == 0 || size > MAX_FILE_SIZE {
		//fmt.Println("ignored because empty or large file")
		ignored_files = append(ignored_files, ignored{path, "empty or too-large file"})
		return nil
	}

	// What is the extension?
	extension := filepath.Ext(path)
	extension = strings.ToLower(extension)

	// Ignore specific extensions
	for _, no_ext := range unwanted_extensions {
		if extension == no_ext {
			return nil
		}
	}

	// Ignore tempory files
	if extension != "" && extension[len(extension)-1] == '~' {
		return nil
	}

	// no extension? Try to guess it
	if extension == "" {
		extension = detect_file_type(path)
	}

	// are we just ranking crypto files?
	if *ranking {
		if extension == ".pem" || extension == ".der" || extension == ".crt" {
			final_rank[100] = append(final_rank[100], path)
		} else {
			if rank := crypto_ranking(path); rank > 0 {
				final_rank[rank] = append(final_rank[rank], path)
			}
		}

		//
		return nil
	}

	// is the format a known key format? (.pem, .der, .asc, ...)
	switch extension {
	case ".pem":
		parse_pem_file(path)
		return nil
	case ".der":
		parse_der_file(path)
		return nil
	case ".crt":
		parse_crt_file(path)
		return nil
	}

	// ignore binary files
	if isBinary(path) {
		ignored_files = append(ignored_files, ignored{path, "binary file"})
		return nil
	}

	// any other format -> parse them
	parse_file(path, extension)

	//
	return nil
}

//
// MAIN
//

func usage() {
	fmt.Println("Usage: ./unicornator (-level 1|2|3) (-no_ignored) [folder or file]")
	fmt.Println("The default level is 2 (warnings), which will not display severity 1 findings (informationals)")
	fmt.Println("Optional arguments:")
	flag.PrintDefaults()
}

func print_headers() {
	fmt.Println("==================================================")
	fmt.Println("=       UNICORNATOR WILL FIND CRYPTO FLAWS       =")
	fmt.Println("==================================================")
}

// main
func main() {

	//
	// Detect Interruption
	//
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println("\n")
		fmt.Println("==================================================")
		fmt.Println("=       UNICORNATOR OUT                          =")
		fmt.Println("==================================================")
		os.Exit(0)
	}()

	//
	// Flags
	//
	level = flag.Int("level", 2, "display level of severity: 1 for informationals, 2 for warnings (default), 3 for important")
	//	html = flag.Bool("html", false, "html output")
	no_ignored = flag.Bool("no_ignored", false, "remove the list of ignored files at the end of the output")
	ranking = flag.Bool("ranking", false, "provides a crypto-ranking (how much 'crypto' a file is)")
	flag.Parse()

	// get directory to visit from argument
	if len(flag.Args()) != 1 {
		usage()

		return
	}

	root := flag.Arg(0)

	// does the directory exist?
	if _, err := os.Stat(root); os.IsNotExist(err) {
		usage()
		return
	}

	// listing ignored files (big binaries)
	ignored_files = make([]ignored, 0)

	// print headers (it's pwetty!)
	print_headers()

	// if we're ranking files, let's create a ranking!
	if *ranking {
		final_rank = make(map[int][]string)
	}

	// walk through each file
	err := filepath.Walk(root, visit)
	if err != nil {
		fmt.Printf("filepath.Walk() returned %v\n", err)
	}

	//
	// OUTPUT
	//

	// print out the ranking
	if *ranking {

		var keys []int
		for key, _ := range final_rank {
			keys = append(keys, key)
		}

		sort.Sort(sort.Reverse(sort.IntSlice(keys)))

		for _, key := range keys {
			for _, path := range final_rank[key] {
				fmt.Println(key, ":", path)
			}
		}
	}

	// print out ignored files
	if !*no_ignored && len(ignored_files) > 0 {
		fmt.Println("\nList of ignored files:\n")

		for _, ignored := range ignored_files {
			fmt.Printf(" * %s: %s\n", ignored.reason, ignored.file)
		}
	}
}
