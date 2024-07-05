package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const version = "1.0.1"

func genRand32ByteKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
func main() {
	encKey := flag.String("e", "", "secret key for encryption (32 byte hex)")
	decKey := flag.String("d", "", "secret key for decryption (32 byte hex)")
	genHexKey := flag.Bool("k", false, "🔑 generates new random 32 byte hex. Warn keep it external and private")
	help := flag.Bool("help", false, "show help")
	ver := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *genHexKey {
		key, err := genRand32ByteKey()
		if err != nil {
			fmt.Printf("unable to generate random key Error: %s", err)
			os.Exit(0)
		}

		fmt.Printf("here is your random secret key 🔑 : %s\n", hex.EncodeToString(key))
		fmt.Println("(save it external, warnning !! this key will not come again !)")
		os.Exit(0)
	}

	if *ver {
		fmt.Printf("att version %s\n", version)
		os.Exit(0)
	}

	if *help || (*encKey == "" && *decKey == "") {
		fmt.Println("🔑🔒 att is your immediate encryption and decryption tool. (keep your secret key outside and private)")
		fmt.Println("Usage: att -e <key> for encryption or att -d <key> for decryption")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *encKey != "" {
		enc(*encKey)
	} else if *decKey != "" {
		dec(*decKey)
	} else {
		fmt.Println("Error: You must provide either -e <key> for encryption or -d <key> for decryption")
		flag.PrintDefaults()
		os.Exit(0)
	}

}

func enc(hexKey string) {
	dirs, err := os.ReadDir(".")
	if err != nil {
		return
	}

	for _, d := range dirs {
		if !d.IsDir() {

			exePath, err := os.Executable()
			if err != nil {
				return
			}

			exeName := filepath.Base(exePath)
			if exeName == d.Name() {
				continue
			}

			part := strings.Split(d.Name(), ".")
			if len(part) > 0 {
				if part[len(part)-1] == "att" {
					continue
				}
			}

			p := path.Join(".", d.Name())

			file, err := os.Open(p)
			if err != nil {
				return
			}

			// original file permission
			fileInfo, err := os.Stat(p)
			if err != nil {
				return
			}

			originalPerm := fileInfo.Mode()

			b, err := io.ReadAll(file)
			if err != nil {
				return
			}

			// encrpt
			byteKey, err := hex.DecodeString(hexKey)
			if err != nil {
				return
			}

			if len(byteKey) != 32 {
				fmt.Println("key must be 32 bytes long")
			}

			// 1 new cipher
			block, e := aes.NewCipher(byteKey)
			if e != nil {
				return
			}

			// 2 new GCM
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return
			}

			// 3 nonce
			nonce := make([]byte, gcm.NonceSize())
			_, err = io.ReadFull(rand.Reader, nonce)
			if err != nil {
				return
			}

			// 4 encrypt
			byteEnc := gcm.Seal(nonce, nonce, b, nil)

			encFile, err := os.Create(d.Name() + ".att")
			if err != nil {
				return
			}

			_, err = encFile.Write(byteEnc)
			if err != nil {
				return
			}

			err = encFile.Chmod(originalPerm)
			if err != nil {
				return
			}

			// remove the orignal file
			err = os.Remove(p)
			if err != nil {
				return
			}

		}
	}
}

func dec(hexKey string) {
	dirs, err := os.ReadDir(".")
	if err != nil {
		return
	}

	for _, d := range dirs {
		if !d.IsDir() {
			p := path.Join(".", d.Name())

			part := strings.Split(d.Name(), ".")
			if len(part) > 0 {
				if part[len(part)-1] != "att" {
					continue
				}
			}

			o := strings.Join(part[:len(part)-1], ".")

			// get original file permissions
			fileInfo, err := os.Stat(p)
			if err != nil {
				return
			}
			originalPerm := fileInfo.Mode()

			file, err := os.Open(p)
			if err != nil {
				return
			}

			rawByte, err := io.ReadAll(file)
			if err != nil {
				return
			}

			// encrpt
			byteKey, err := hex.DecodeString(hexKey)
			if err != nil {
				return
			}

			if len(byteKey) != 32 {
				fmt.Println("key must be 32 bytes long")
			}

			// 1 new cipher
			block, e := aes.NewCipher(byteKey)
			if e != nil {
				return
			}

			// 2 new GCM
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return
			}

			// check
			nonceSize := gcm.NonceSize()
			if len(rawByte) < nonceSize {
				continue
			}

			// extract
			nonce, encByte := rawByte[:nonceSize], rawByte[nonceSize:]

			byteDec, err := gcm.Open(nil, nonce, encByte, nil)
			if err != nil {
				continue
			}

			// file with decrypted content
			err = os.WriteFile(o, byteDec, originalPerm)
			if err != nil {
				return
			}

			// remove the dec file
			err = os.Remove(p)
			if err != nil {
				return
			}

		}
	}
}
