package main

import (
	"crypto/x509"
)

// good signature algorithms
var whitelist_signature_algorithm = map[string]bool{
	"ECDSA-SHA256": true,
	"ECDSA-SHA512": true,
	"ECDSA-SHA384": true,
	"SHA256-RSA":   true,
	"SHA384-RSA":   true,
	"SHA512-RSA":   true,
	//"DSA-SHA256": true,
}

var whitelist_public_key_algorithm = map[x509.PublicKeyAlgorithm]bool{
	x509.RSA:   true,
	x509.ECDSA: true,
	//x509.DH: true, // DH doesn't exist in Go :/
}

var unwanted_paths = []string{
	".git/",
	".svn/",
	"test",
	"Test",
	"TEST",
	"openssl/",
	"OpenSSL/",
	"jquery",
	"min.js",
	"LICENSE",
}

var unwanted_extensions = []string{
	// executable
	".exe",
	".dmg",
	// binaries
	".so",
	".bin",
	".jar",
	// archives/compressed files
	".zip",
	".tar",
	".gz",
	".7z",
	".a",
	// image
	".jpg",
	".png",
	".jpeg",
	".bmp",
	".ico",
	".gif",
	// av
	".ogg",
	".avi",
	".mp4",
	".mp3",
	".mpeg",
	".mov",
	".wav",
	// program files
	".doc",
	".docx",
	".pdf",
	".psd",
	".ai",
	".fla",
	".swf",
	// useless languages
	".css",
	".asm",
	// useless to parse
	".pcap",
	".cap",
	// txt file
	".md",
	".txt",
	// structure files
	".xml",
	".json",
	// fonts
	".ttf",
	".eot",
	".otf",
	// apple
	".storyboard",
}
