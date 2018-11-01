package server

import (
	"bufio"
	"log"
	"os"
	"strings"
)

const (
	MaxAlpha = 16
	MinAlpha = 1
)

func Load(filepath string) Tree {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	t := Tree{nil}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := strings.Split(scanner.Text()," ")
		user, pass := s[0], s[1]
		if validatePair(user,pass) {
			t.Add(user,pass)
		}
	}

	return t
}


func validatePair(userName string, password string) bool {

	for _, c := range userName {
		let := string(c)

		if (let != "." && let != "-" && let != "_") &&
			(let < "0" || (let > "9" && let < "A") ||
				(let > "Z" && let < "a") || let > "z") {
			return false
		}
	}
	return len(userName) >= MinAlpha && len(userName) <= MaxAlpha
}