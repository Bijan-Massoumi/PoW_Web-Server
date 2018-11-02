package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"crypto/sha256"
	"math/rand"
	"os"
	"strings"
	"time"
)

const (
	ConnHost = "localhost"
	ConnPort = "8987"
	ConnType = "tcp"
)


type TestResult struct {
	result byte
	username string
}

func main() {
	file, err := os.Open("PoW_Web-Server/main/input.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	//load the db textfile in for testing. Not all are valid
	b, err := ioutil.ReadAll(file)
	lines := strings.Split(string(b),"\n")
	c := make(chan TestResult, 100)
	numThreads := 100
	for i:=0; i < numThreads; i+= 1 {
		//pick random user/pass pair
		inputs := strings.Split(lines[rand.Intn(len(lines))]," ")
		//wait one ms between dials to avoid a few RSTs by server.
		time.Sleep(1* time.Millisecond)
		go query(inputs[0], inputs[1], c)
	}
	for i:=0; i < numThreads; i+= 1 {
		//prints out the byte status for every goroutine query
		fmt.Println(<-c)
	}
}



func query(userName string, password string, c chan TestResult) {
	buf := make([]byte, 1024)
	conn, errConn := net.Dial(ConnType, ConnHost + ":" + ConnPort)

	if errConn != nil {
		fmt.Println("pre-error: ", errConn)
		return
	}

	var Ns []byte
	var strength byte
	// get nonce and strength
	i := 0
	for {
		len, err := conn.Read(buf)

		if err != nil {
			fmt.Println(i, "error: ", err)
			break
		}
		if len > 1 {
			Ns = make([]byte,len)
			copy(Ns, buf[0:len])
		} else {
			strength = byte(buf[0])
		}

		if i += 1; i == 2 {
			break
		}

	}

	Nc, v := proofOfWork(Ns,strength,userName,password)

	//send Work
	conn.Write([]byte(userName + "\x00"))
	time.Sleep(100 * time.Millisecond)
	conn.Write([]byte(v))
	time.Sleep(100 * time.Millisecond)
	conn.Write([]byte(Nc))
	time.Sleep(100 * time.Millisecond)

	//listen for status
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println("error: ", err)
	}
	//work accepted status
	c <- TestResult{buf[0],userName}

	conn.Close()
}

func proofOfWork(Ns []byte, strength byte, userName string,password string) ([]byte, []byte) {
	for {
		b1, b2, b3, b4 := make([]byte, 8), make([]byte, 8), make([]byte, 8), make([]byte, 8)
		for _, v := range [][]byte{b1,b2,b3,b4} {
			binary.LittleEndian.PutUint64(v, rand.Uint64())
		}
		Nc := append(append(append(b1,b2...),b3...),b4...)

		arrToHash := append(append(Ns,[]byte(userName + "\x00" + password + "\x00")...), Nc...)
		hash := sha256.Sum256(arrToHash)
		if validHash(hash[:], strength) {
			return Nc, hash[:]
		}
	}
}

func validHash(hash []byte, strength byte) bool {
	var leftByte = 0
	var rightByte = len(hash) - 1
	var leftBit = byte(1 << 7)
	var rightBit = byte(1)
	for i:= byte(0); i < strength; i++ {
		if i > 0 && i % 8 == 0 {
			leftByte++
			rightByte--
			leftBit = 1 << 7
			rightBit = 1
		}
		if (hash[leftByte] & leftBit == 0) != (hash[rightByte] & rightBit == 0) {
			return false;
		}
		leftBit >>= 1
		rightBit <<= 1
	}
	return true;
}

