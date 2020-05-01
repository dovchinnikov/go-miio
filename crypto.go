package miio

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/md5"
)

type deviceKeys struct {
	key [16]byte
	iv  [16]byte
}

func deviceKeysFromToken(token *[16]byte) deviceKeys {
	key := md5(token[:])
	return deviceKeys{
		key,
		md5(key[:], token[:]),
	}
}

func md5(chunks ...[]byte) [16]byte {
	hash := crypto.MD5.New()
	for _, chunk := range chunks {
		hash.Write(chunk)
	}
	var result [16]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (keys *deviceKeys) encrypt(data []byte) []byte {
	mode := cipher.NewCBCEncrypter(keys.newCipher(), keys.iv[:])
	padded := pad(data, mode.BlockSize())
	result := make([]byte, len(padded))
	mode.CryptBlocks(result, padded)
	return result
}

func pad(data []byte, blockSize int) []byte {
	dataLen := len(data)
	padding := blockSize - dataLen%blockSize
	result := make([]byte, dataLen+padding)
	copy(result, data)
	padByte := byte(padding)
	for i := 0; i < padding; i++ {
		result[dataLen+i] = padByte
	}
	return result
}

func decrypt(keys deviceKeys, data []byte) []byte {
	mode := cipher.NewCBCDecrypter(keys.newCipher(), keys.iv[:])
	result := make([]byte, len(data))
	mode.CryptBlocks(result, data)
	return result
}

func (keys *deviceKeys) newCipher() cipher.Block {
	block, err := aes.NewCipher(keys.key[:])
	if err != nil {
		panic(err)
	}
	return block
}
