package main

import (
  "fmt"
	"encoding/pem"
	"crypto/x509"
	"time"
	"crypto/rsa"
	"crypto/dsa"
	"crypto/ecdsa"
)



var objIdToName = map[string]string{
	"2.5.29.1": "old Authority Key Identifier",
	"2.5.29.2": "old Primary Key Attributes",
	"2.5.29.3": "Certificate Policies",
	"2.5.29.4": "Primary Key Usage Restriction",
	"2.5.29.9": "Subject Directory Attributes",
	"2.5.29.14": "Subject Key Identifier",
	"2.5.29.15": "Key Usage",
	"2.5.29.16": "Private Key Usage Period",
	"2.5.29.17": "Subject Alternative Name",
	"2.5.29.18": "Issuer Alternative Name",
	"2.5.29.19": "Basic Constraints",
	"2.5.29.20": "CRL Number",
	"2.5.29.21": "Reason code",
	"2.5.29.23": "Hold Instruction Code",
	"2.5.29.24": "Invalidity Date",
	"2.5.29.27": "Delta CRL indicator",
	"2.5.29.28": "Issuing Distribution Point",
	"2.5.29.29": "Certificate Issuer",
	"2.5.29.30": "Name Constraints",
	"2.5.29.31": "CRL Distribution Points",
	"2.5.29.32": "Certificate Policies",
	"2.5.29.33": "Policy Mappings",
	"2.5.29.35": "Authority Key Identifier",
	"2.5.29.36": "Policy Constraints",
	"2.5.29.37": "Extended key usage",
	"2.5.29.46": "FreshestCRL",
	"2.5.29.54": "X.509 version 3 certificate extension Inhibit Any-policy ",
}

// todo:
// * check for use of Golang Exp function without checking if it can be 0 first.
// * and stuff like that...

// should publicKey be of type interface{} ?
func check_public_key(publicKey interface{}, algorithm x509.PublicKeyAlgorithm) {
	/*
	switch algorithm {
	default:
		fmt.Println(" - can't recognize the public key algorithm, contact the author of this tool")
	case x509.RSA:
		fmt.Println(" - RSA key")
		check_RSA_public_key(publicKey)
	case x509.ECDSA:
		fmt.Println(" - ECDSA key")
		//check_ECDSA_public_key()
	}*/
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		fmt.Println(" - RSA public key")
		check_RSA_public_key(pub)
	case *ecdsa.PublicKey:
		fmt.Println(" - ECDSA public key")
	default:
		fmt.Println(" - couldn't detect the public key")
	}	

}

func detect_pem_private_key(der_content *pem.Block) bool {
	
	// detect something of value "010001" or 3 -> RSA
	// detect common curve points, or compressed points
	// detect common DSA group. Detect bad groups and backdoored groups!

	return true
}

//
func check_RSA_public_key(publicKey *rsa.PublicKey) {
	// test the modulus
	if bitlen := publicKey.N.BitLen(); bitlen < 2048 {
		fmt.Println(" x RSA key has a weak modulus (<2048bits) of", bitlen, "bits.")
	}
}

//
func check_pem_public_key(der_content *pem.Block) bool {

	pub, err := x509.ParsePKIXPublicKey(der_content.Bytes)
	if err != nil {
		fmt.Println(" x can't parse the public key:\n", der_content)
		return false
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		check_RSA_public_key(pub)
	case *dsa.PublicKey:
		fmt.Println(" - pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		fmt.Println(" - pub is of type ECDSA:", pub)
	default:
		fmt.Println(" x unknown type of public key")
	}

	return true
}

func check_certificate(der_content []byte) bool {
	// parse the certificate
	cert, err := x509.ParseCertificate(der_content)
	if err != nil {
		fmt.Println(" x can't parse the certificate")
		return false
	}
	// check signature algorithm
	SA := cert.SignatureAlgorithm.String()
	if!whitelist_signature_algorithm[SA] {
		fmt.Println(" x bad signature algorithm for that certificate: ", SA)
	}

	// check public key algorithm
	if PA := cert.PublicKeyAlgorithm; !whitelist_public_key_algorithm[PA] {
		fmt.Println(" x bad public key algorithm for that certificate: ", PA)
	}

	// subject
	fmt.Println(" - subject:", cert.Subject.CommonName)

	// check public key
	check_public_key(cert.PublicKey, cert.PublicKeyAlgorithm)

	// expiry dates
	fmt.Println(" - not before:", cert.NotBefore)
	fmt.Println(" - not after: ", cert.NotAfter)

	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		fmt.Println(" x cert is not currently valid")
	}
	
	// print isCA, basicConstraints, NameConstraints, keyUsage
/*
Issuer: {
        Country, Organization, OrganizationalUnit []string
        Locality, Province                        []string
        StreetAddress, PostalCode                 []string
        SerialNumber, CommonName                  string

        Names      []AttributeTypeAndValue
        ExtraNames []AttributeTypeAndValue
}
*/

	fmt.Println(" - is CA:", cert.IsCA)

	if cert.Issuer.CommonName == cert.Subject.CommonName {
		fmt.Println(" - self signed")
	} else {
		fmt.Println(" - issuer:", cert.Issuer.CommonName)
	}

	// extensions
	for _, extension := range cert.Extensions {
		if extension.Critical {
			fmt.Println(" - critical cert extension:")
		} else {
			fmt.Println(" - cert extension:")
		}
			
		fmt.Println("   + id:", extension.Id)

		extension_name := objIdToName[extension.Id.String()]
		fmt.Println("   + id:", extension_name)
		if extension_name ==  "Subject Alternative Name" {
			fmt.Printf("   + value: %s\n", extension.Value)
		} else {
			fmt.Println("   + value:", extension.Value)
		}

	}

	// key extension

	// extra extensions
	// 
	return true
}


