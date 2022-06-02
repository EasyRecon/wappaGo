package lib

import (
	"io/fs"
	"math/rand"
	"path/filepath"

	"github.com/EasyRecon/wappaGo/structure"
)

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = structure.LetterBytes[rand.Intn(len(structure.LetterBytes))]
	}
	return string(b)
}
func CheckIpAlreadyScan(ip string, list []structure.PortOpenByIp) structure.PortOpenByIp {
	for _, ipScanned := range list {
		if ip == ipScanned.IP {
			return ipScanned
		}
	}
	return structure.PortOpenByIp{}
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func GetKey(array map[string]interface{}) []string {
	k := make([]string, len(array))
	i := 0
	for s, _ := range array {
		k[i] = s
		i++
	}
	return k
}
func Find(root, ext string) []string {
	var a []string
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	return a
}
