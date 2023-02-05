package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/joho/godotenv"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"log"
)

const (
	HEADER_LENGTH = 1024
	CONNECT       = 0
	MESSAGE       = 1
	RESPONSE      = 2
	ERROR         = 3
	DISCONNECT    = 4
)

var (
	prime = []byte(os.Getenv("PRIME"))
	base  = big.NewInt(2)
)

func CheckError(e error) {
	if e != nil {
		fmt.Println(e)
	}
}

func write_to_file(filename string, text string) {
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		CheckError(err)
		file.WriteString(text)
		file.Close()
	} else {
		file, err := os.Open(filename)
		CheckError(err)
		file.WriteString(text)
		file.Close()
	}
}

type Server struct {
	HostName    string
	Host        string
	Port        string
	Socket      net.Listener
	PrivKey     *big.Int
	PubKey      *big.Int
	AESKey      string
	Addresses   []net.Addr
	Connections []net.Conn
}

func encrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	CheckError(err)
	gcm, err := cipher.NewGCM(block)
	CheckError(err)
	iv := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, iv)
	ciphertext := gcm.Seal(iv, iv, data, nil)
	buf := make([]byte, 5)
	_, err = rand.Read(buf)
	CheckError(err)
	ciphertext = append(buf, ciphertext...)
	return ciphertext
}

func decrypt(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	CheckError(err)
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[5:17]
	ciphertext = ciphertext[17:]
	gcm, err := cipher.NewGCM(block)
	CheckError(err)
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	CheckError(err)
	return plaintext
}

func (s *Server) send(conn net.Conn, action int, data string) {
	key, _ := hex.DecodeString(s.AESKey)
	encrypted_data := encrypt([]byte(data), key)
	length := fmt.Sprint(len(encrypted_data))
	encrypted_header := encrypt([]byte(fmt.Sprint(action)+length), key)
	buffer := strings.Repeat(" ", HEADER_LENGTH-len(encrypted_header))
	conn.Write([]byte(string(encrypted_header) + buffer + string(encrypted_data)))
}

func (s *Server) receive(conn net.Conn) (int, string) {
	key, _ := hex.DecodeString(s.AESKey)
	reader := bufio.NewReader(conn)
	header := make([]byte, HEADER_LENGTH)
	reader.Read(header)
	decrypted_header := decrypt([]byte(strings.TrimSpace(string(header))), key)
	action, err := strconv.Atoi(string(decrypted_header[0]))
	CheckError(err)
	length, err := strconv.Atoi(string(decrypted_header[1:]))
	CheckError(err)
	data := make([]byte, length)
	reader.Read(data)
	return action, string(decrypt(data, key))
}

func (s *Server) generatePrivateKey() {
	priv_key := make([]byte, 540)
	_, err := rand.Read(priv_key)
	CheckError(err)
	s.PrivKey = new(big.Int).SetBytes(priv_key)
}

func (s *Server) generatePublicKey() {
	parsed_prime := big.NewInt(0)
	parsed_prime.UnmarshalText(prime)
	var pub_key big.Int
	pub_key.Exp(base, s.PrivKey, parsed_prime)
	s.PubKey = &pub_key
}

func (s *Server) performKeyExchange(conn net.Conn) {
	reader := bufio.NewReader(conn)
	header := make([]byte, HEADER_LENGTH)
	reader.Read(header)
	length, err := strconv.Atoi(strings.TrimSpace(string(header)))
	CheckError(err)
	data := make([]byte, length)
	reader.Read(data)
	remote_pub_key := data
	key_length := fmt.Sprint(len(s.PubKey.Bytes()))
	buffer := strings.Repeat(" ", HEADER_LENGTH-len(key_length))
	send_header := key_length + buffer
	conn.Write(append([]byte(send_header), s.PubKey.Bytes()...))
	s.getKey(remote_pub_key)
}

func (s *Server) getKey(remote_pub_key []byte) {
	pub_key_int := big.NewInt(0)
	pub_key_int.SetBytes(remote_pub_key)
	parsed_prime := big.NewInt(0)
	parsed_prime.UnmarshalText(prime)
	var shared_secret big.Int
	shared_secret.Exp(pub_key_int, s.PrivKey, parsed_prime)
	hash := sha256.New()
	hash.Write(shared_secret.Bytes())
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	s.AESKey = mdStr
	fmt.Println("Key: ", mdStr)
}

func (s *Server) handle_connection(conn net.Conn) {
	s.generatePrivateKey()
	s.generatePublicKey()
	s.performKeyExchange(conn)
	for {
		action, message := s.receive(conn)
		fmt.Println(message)
		if action == CONNECT {
			s.send(conn, CONNECT, "Connected!")
			continue
		}
		if action == DISCONNECT {
			s.send(conn, DISCONNECT, "")
			continue
		}
		if action == MESSAGE {
			s.send(conn, RESPONSE, message)
		}
	}
}

func (s *Server) accept_connections() {
	for {
		conn, err := s.Socket.Accept()
		CheckError(err)
		s.Addresses = append(s.Addresses, conn.RemoteAddr())
		s.Connections = append(s.Connections, conn)
	}
}

func (s *Server) list_connections() {
	for i, address := range s.Addresses {
		fmt.Println("[", i+1, "]", address.String())
	}
}

func (s *Server) start() {
	fmt.Println("Starting server...")
	var err error
	s.Socket, err = net.Listen("tcp", s.Host+":"+s.Port)
	CheckError(err)
	fmt.Println("Server listening onport "+s.Port+"!")
	fmt.Println("Waiting for inoming connections...")
}

func (s *Server) run_dashboard() {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter command: ")
		cmd, err := reader.ReadString('\n')
		CheckError(err)
		args := strings.Split(strings.TrimSpace(cmd), " ")
		if args[0] == "list" {
			s.list_connections()
		}
		if args[0] == "select" {
			index, err := strconv.Atoi(args[1])
			CheckError(err)
			conn := s.Connections[index-1]
			s.handle_connection(conn)
		}
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	name, err := os.Hostname()
	CheckError(err)
	server := Server{
		HostName: name,
		Host:     os.Getenv("HOST"),
		Port:     os.Getenv("PORT"),
	}
	server.start()
	go server.accept_connections()
	server.run_dashboard()
}
