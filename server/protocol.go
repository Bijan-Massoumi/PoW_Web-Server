package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"crypto/rand"
	"strconv"
	"time"
	"unicode/utf8"
)

var PowStrength byte = 4 //from 0 - 128

func HandlePoWProtocol(conn net.Conn, db Tree) {
	// Make a buffer to hold incoming data.
	hasPassedInputChecks := true
	buf := make([]byte, 1024)
	Ns := make([]byte, 32)
	Nc, v :=  make([]byte,32), make([]byte,32)
	var userName []byte
	rand.Read(Ns)
	//send 32 byte random nonce
	conn.Write(Ns)
	time.Sleep(10 * time.Millisecond)
	//send POW difficulty
	conn.Write([]byte{PowStrength})
	// Read the incoming username, V and NC
	i := 0
	for i < 3 {
		reqLen, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			break
		}
		if i == 0 {
			if reqLen == 0 || !validUnicode(buf[:reqLen]) {
				hasPassedInputChecks = false
				break
			}
			//recevie usersname first
			userName = make([]byte, reqLen)
			copy(userName,buf[0:reqLen])
		} else if i == 1 {
			//receive V second
			copy(v ,buf[0:reqLen])
		} else {
			//receive Proof last
			copy(Nc ,buf[0:reqLen])
		}
		i += 1
	}
	//send confirmation byte
	if hasPassedInputChecks && verifyWork(string(userName[0:len(userName)-1]), Ns, Nc, v, db) {
		conn.Write([]byte{1})
	} else {
		conn.Write([]byte{0})
	}

	time.Sleep(10 * time.Millisecond)
	fmt.Println("closing connection")
	conn.Close()
}


//private methods-----------------

func validUnicode(userName []byte) bool {
	if userName[len(userName)-1] == byte(0) && utf8.RuneCount(userName) <= 17 {
		return true
	}
	return false
}

func verifyWork(userName string, Ns []byte, Nc []byte, v[]byte, db Tree) bool {
	//verify hash first
	if !validHash(v,PowStrength) {
		return false
	}
	node := db.Find(userName)
	if node == nil {
		return false
	}
	//verify the work
	arrToHash := append(append(Ns,[]byte(userName + "\x00" + node.password + "\x00")...), Nc...)
	hash := sha256.Sum256(arrToHash)
	return checkEq(hash[:],v)
}

func validHash(hash []byte, strength byte) bool{
	binaryRep := convertToBinary(hash)
	for i := 0; i < int(strength); i++ {
		if binaryRep[i] != binaryRep[len(binaryRep)-1-i] {
			return false
		}
	}
	return true
}

func convertToBinary(hash []byte) string {
	var buffer bytes.Buffer
	for _, x := range(hash) {
		buffer.WriteString(strconv.FormatUint(uint64(x), 2))
	}
	return buffer.String()
}

func checkEq(hash1 []byte, hash2 []byte ) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	for i:= 0; i < len(hash1); i++ {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	return true
}