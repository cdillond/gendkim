package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"os"
)

func main() {
	var (
		f       *os.File
		err     error
		pubKey  ed25519.PublicKey
		privKey ed25519.PrivateKey
		srcData []byte
		pb      *pem.Block
	)

	var (
		recordPath  = flag.String("record", "dkim-record.txt", "output path of the DKIM record content")
		pubKeyPath  = flag.String("pubkey", "pubkey.pem", "output path of the PEM-encoded public key")
		privKeyPath = flag.String("privkey", "privkey.pem", "output path of the PEM-encoded private key")
		fromPrivKey = flag.String("from", "", "optional input path of the PEM-encoded private key; if no value is provided, a new key is generated")
		fromSeed    = flag.String("seed", "", "optional input path of the private key seed")
	)

	flag.Parse()

	// load or create the private key and generate the public key
	if *fromPrivKey != "" {
		if srcData, err = os.ReadFile(*fromPrivKey); err != nil {
			panic(err)
		}
		if pb, _ = pem.Decode(srcData); pb == nil {
			panic(errors.New("unable to decode private key"))
		}
		if len(pb.Bytes) != ed25519.PrivateKeySize {
			panic(errors.New("private key length must be exactly 64 bytes"))
		}
		privKey = ed25519.PrivateKey(pb.Bytes)
		// this type assertion will always succeed,
		pubKey = privKey.Public().(ed25519.PublicKey)

	} else if *fromSeed != "" {
		if srcData, err = os.ReadFile(*fromPrivKey); err != nil {
			panic(err)
		}
		// this function panics on failure
		privKey = ed25519.NewKeyFromSeed(srcData)
		// this type assertion will always succeed,
		pubKey = privKey.Public().(ed25519.PublicKey)

	} else {
		pubKey, privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
	}

	const prefix = "v=DKIM1; k=ed25519; p="
	// per rfc8463, the base encoded key is always "44 octets"
	pubRecord := make([]byte, len(prefix), len(prefix)+44)
	copy(pubRecord, []byte(prefix))
	pubRecord = base64.StdEncoding.AppendEncode(pubRecord, []byte(pubKey))

	if f, err = os.Create(*recordPath); err != nil {
		panic(err)
	}
	if _, err = f.Write(pubRecord); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}

	pb = new(pem.Block)
	// encode and write private key
	pb.Type = "PRIVATE KEY"
	pb.Bytes = privKey[:]
	if f, err = os.Create(*privKeyPath); err != nil {
		panic(err)
	}
	if err = pem.Encode(f, pb); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}

	// encode and write public key
	pb.Type = "PUBLIC KEY"
	pb.Bytes = pubKey[:]
	if f, err = os.Create(*pubKeyPath); err != nil {
		panic(err)
	}
	if err = pem.Encode(f, pb); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}
}
