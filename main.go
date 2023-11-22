package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// VERSION!!!

// REQUEST
// VersionRequestPacket represents a packet of type 5000 that contains the client version
type VersionRequestPacket struct {
    Version uint16 // The client version
}

// ParseVersionRequestPacket parses a byte slice into a VersionRequestPacket
func ParseVersionRequestPacket(data []byte) *VersionRequestPacket {
    // Create a new VersionRequestPacket
    packet := &VersionRequestPacket{}
    // Read the version from the data
    packet.Version = binary.LittleEndian.Uint16(data[4:6])
    // Return the packet
    return packet
}

// RESPONSE
// VersionResponsePacket represents a packet of type 5001 that contains the server version
type VersionResponsePacket struct {
    Version uint16 // The server version
}

// GetBytes converts a VersionResponsePacket into a byte slice
func (p *VersionResponsePacket) GetBytes() []byte {
    // Create a byte buffer
    buf := new(bytes.Buffer)
    // Write the packet type
    binary.Write(buf, binary.LittleEndian, uint16(5001))
    // Write the packet length
    binary.Write(buf, binary.LittleEndian, uint16(6))
    // Write the version
    binary.Write(buf, binary.LittleEndian, p.Version)
    // Return the buffer bytes
    return buf.Bytes()
}

// HandleVersionRequestPacket handles a VersionRequestPacket and sends a VersionResponsePacket to the client
func HandleVersionRequestPacket(packet *VersionRequestPacket, conn net.Conn) {
    // Create a version response packet with the server version
    response := &VersionResponsePacket{ Version: packet.Version }
    // Get the bytes of the response packet
    data := response.GetBytes()
    // Write the data to the connection
    _, err := conn.Write(data)
    if err != nil {
        fmt.Println("Error writing data to", conn.RemoteAddr(), ":", err)
        conn.Close()
        return
    }
    // Print a message
    fmt.Println("Sent version response to", conn.RemoteAddr(), "with version", packet.Version)
}


// PacketType is an enum for packet types
type PacketType uint16

const (
	// LoginRequest is the packet type for login request
	LoginRequest PacketType = 1000
	// LoginResponse is the packet type for login response
	LoginResponse PacketType = 1001
	// TokenRequest is the packet type for token request
	TokenRequest PacketType = 2000
	// TokenResponse is the packet type for token response
	TokenResponse PacketType = 2001
)

// Packet is an interface for packets
type Packet interface {
	// GetType returns the packet type
	GetType() PacketType
	// GetBytes returns the packet bytes
	GetBytes() []byte
}

// LoginRequestPacket is a struct for login request packet
type LoginRequestPacket struct {
	// Login is the user login
	Login string
	// Password is the user password
	Password string
	// Version is the client version
	Version string
}

// GetType returns the packet type
func (p *LoginRequestPacket) GetType() PacketType {
	return LoginRequest
}

// GetBytes returns the packet bytes
func (p *LoginRequestPacket) GetBytes() []byte {
	// Create a byte slice with length 64
	data := make([]byte, 64)
	// Write the packet length (64) at the beginning
	binary.LittleEndian.PutUint16(data[0:2], 64)
	// Write the packet type (1000) after the length
	binary.LittleEndian.PutUint16(data[2:4], uint16(p.GetType()))
	// Write the login as ASCII string, padded with zeros if shorter than 16 characters
	copy(data[4:20], []byte(p.Login))
	// Write the password as ASCII string, padded with zeros if shorter than 16 characters
	copy(data[36:52], []byte(p.Password))
	// Write the version as ASCII string, padded with zeros if shorter than 8 characters
	copy(data[52:60], []byte(p.Version))
	// Return the data
	return data
}

// LoginResponsePacket is a struct for login response packet
type LoginResponsePacket struct {
	// Token is the access token
	Token string
	// Servers is the list of game servers
	Servers []GameServerInfo
}

// GetType returns the packet type
func (p *LoginResponsePacket) GetType() PacketType {
	return LoginResponse
}

// GetBytes returns the packet bytes
func (p *LoginResponsePacket) GetBytes() []byte {
	// Calculate the packet length as 34 + 38 * number of servers
	length := 34 + 38*len(p.Servers)
	// Create a byte slice with the calculated length
	data := make([]byte, length)
	// Write the packet length at the beginning
	binary.LittleEndian.PutUint16(data[0:2], uint16(length))
	// Write the packet type (1001) after the length
	binary.LittleEndian.PutUint16(data[2:4], uint16(p.GetType()))
	// Write the token as ASCII string
	copy(data[4:36], []byte(p.Token))
	// Write the number of servers after the token
	binary.LittleEndian.PutUint16(data[36:38], uint16(len(p.Servers)))
	// Write the information of each server after the number of servers
	for i, server := range p.Servers {
		// Calculate the offset for the current server
		offset := 38 + i*38
		// Write the server ID as a uint16
		binary.LittleEndian.PutUint16(data[offset:offset+2], server.ID)
		// Write the server name as ASCII string, padded with zeros if shorter than 16 characters
		copy(data[offset+2:offset+18], []byte(server.Name))
		// Write the server status as a uint16
		binary.LittleEndian.PutUint16(data[offset+18:offset+20], server.Status)
		// Write the server IP as ASCII string, padded with zeros if shorter than 16 characters
		copy(data[offset+20:offset+36], []byte(server.IP))
		// Write the server port as a uint16
		binary.LittleEndian.PutUint16(data[offset+36:offset+38], server.Port)
	}
	// Return the data
	return data
}

// TokenRequestPacket is a struct for token request packet
type TokenRequestPacket struct {
	// Token is the access token
	Token string
}

// GetType returns the packet type
func (p *TokenRequestPacket) GetType() PacketType {
	return TokenRequest
}

// GetBytes returns the packet bytes
func (p *TokenRequestPacket) GetBytes() []byte {
	// Create a byte slice with length 36
	data := make([]byte, 36)
	// Write the packet length (36) at the beginning
	binary.LittleEndian.PutUint16(data[0:2], 36)
	// Write the packet type (2000) after the length
	binary.LittleEndian.PutUint16(data[2:4], uint16(p.GetType()))
	// Write the token as ASCII string
	copy(data[4:36], []byte(p.Token))
	// Return the data
	return data
}

// TokenResponsePacket is a struct for token response packet
type TokenResponsePacket struct {
	// Session is the session ID
	Session uint32
}

// GetType returns the packet type
func (p *TokenResponsePacket) GetType() PacketType {
	return TokenResponse
}

// GetBytes returns the packet bytes
func (p *TokenResponsePacket) GetBytes() []byte {
	// Create a byte slice with length 8
	data := make([]byte, 8)
	// Write the packet length (8) at the beginning
	binary.LittleEndian.PutUint16(data[0:2], 8)
	// Write the packet type (2001) after the length
	binary.LittleEndian.PutUint16(data[2:4], uint16(p.GetType()))
	// Write the session ID as a uint32
	binary.LittleEndian.PutUint32(data[4:8], p.Session)
	// Return the data
	return data
}

// GameServerInfo is a struct for game server information
type GameServerInfo struct {
	// ID is the server ID
	ID uint16
	// Name is the server name
	Name string
	// Status is the server status
	Status uint16
	// IP is the server IP
	IP string
	// Port is the server port
	Port uint16
}

// AuthServer is a struct for authorization server
type AuthServer struct {
	// Address is the server address
	Address string
	// Listener is the TCP listener
	Listener net.Listener
	// Users is the map of users with login as key and password as value
	Users map[string]string
	// Servers is the list of game servers
	Servers []GameServerInfo
}

// NewAuthServer creates a new authorization server
func NewAuthServer(address string) *AuthServer {
	// Create a new auth server with the given address
	server := &AuthServer{
		Address: address,
	}
	// Initialize the map of users
	server.Users = make(map[string]string)
	// Hardcode some users for testing
	server.Users["user"] = "pass"
	server.Users["admin"] = "admin"
	// Initialize the list of game servers
	server.Servers = []GameServerInfo{
		{ID: 1, Name: "Alpha", Status: 1, IP: "12.34.56.78", Port: 8080},
		{ID: 2, Name: "Beta", Status: 1, IP: "12.34.56.79", Port: 8081},
	}
	// Return the server
	return server
}

// Start starts the authorization server
func (s *AuthServer) Start() error {
	// Create a TCP listener on the server address
	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		return err
	}
	// Save the listener
	s.Listener = listener
	// Print a message
	fmt.Println("Authorization server started on", s.Address)
	// Accept connections in a loop
	for {
		// Accept a connection
		conn, err := s.Listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		// Print a message
		fmt.Println("Accepted connection from", conn.RemoteAddr())
		// Handle the connection in a goroutine
		go s.HandleConnection(conn)
	}
}

// HandleConnection handles a connection 
func (s *AuthServer) HandleConnection(conn net.Conn) { 
	// Create a buffer for reading data 
	buf := make([]byte, 64) // Read data from the connection
	fmt.Println("buf: ", buf)
	n, err := conn.Read(buf)
	fmt.Println("n: ", n)
	if err != nil { 
		fmt.Println("Error reading data from", conn.RemoteAddr(), ":", err)
		conn.Close()

		return 
	}
	// Parse the packet type and length
	packetType := binary.LittleEndian.Uint16(buf[:2])
	packetLength := binary.LittleEndian.Uint16(buf[2:4])
	// Check if the packet type is 5000
	if packetType == 5000 {
		// Check if the packet length is 6
		if packetLength != 6 {
			fmt.Println("Invalid packet length from", conn.RemoteAddr())
			conn.Close()
			return
		}
		// Parse and handle the version request packet
		// ...
		fmt.Println("qq!")
	}
	// Check if the packet type is 5100
	if packetType == 5100 {
		// Check if the packet length is 34
		if packetLength != 34 {
			fmt.Println("Invalid packet length from", conn.RemoteAddr())
			conn.Close()
			return
		}
		// Parse and handle the login request packet
		// ...
	}
	// Parse the data as a login request packet 
	packet := s.ParseLoginRequestPacket(buf[:n]) 
	fmt.Println("packet: ", packet)
	if packet == nil { 
		fmt.Println("Invalid packet from", conn.RemoteAddr())
		conn.Close()

		return 
	} 
	// Print a message 
	fmt.Println("Received login request from", conn.RemoteAddr(), "with login", packet.Login, "and password", packet.Password)
	// Check if the user exists and the password is correct 
	password, ok := s.Users[packet.Login] 
	if !ok || password != packet.Password { 
		fmt.Println("Invalid login or password from", conn.RemoteAddr())
		conn.Close()

		return
	}
	// Generate a random token 
	token := s.GenerateToken()
	// Create a login response packet with the token and the list of game servers 
	response := &LoginResponsePacket{ Token: token, Servers: s.Servers, } 
	// Get the bytes of the response packet 
	data := response.GetBytes() 
	// Write the data to the connection 
	_, err = conn.Write(data) 
	if err != nil { 
		fmt.Println("Error writing data to", conn.RemoteAddr(), ":", err)
		conn.Close()
		return
	} 
	// Print a message 
	fmt.Println("Sent login response to", conn.RemoteAddr(), "with token", token, "and", len(s.Servers), "servers") 
	// Close the connection 
	conn.Close() 
}

// ParseLoginRequestPacket parses a byte slice as a login request packet 
func (s *AuthServer) ParseLoginRequestPacket(data []byte) *LoginRequestPacket {
	// Check if the data length is 64 
	if len(data) != 64 { 
		return nil
	} 
	// Check if the packet type is 1000 
	if binary.LittleEndian.Uint16(data[2:4]) != uint16(LoginRequest) { return nil } 
	// Create a new login request packet 
	packet := &LoginRequestPacket{} 
	// Read the login as ASCII string, trimming the zeros 
	packet.Login = strings.TrimRight(string(data[4:20]), "\x00") 
	// Read the password as ASCII string, trimming the zeros 
	packet.Password = strings.TrimRight(string(data[36:52]), "\x00") 
	// Read the version as ASCII string, trimming the zeros 
	packet.Version = strings.TrimRight(string(data[52:60]), "\x00") 
	// Return the packet 
	return packet 
}

// GenerateToken generates a random token 
func (s *AuthServer) GenerateToken() string { 
	// Create a byte slice with length 32 
	token := make([]byte, 32) 
	// Create a random source 
	source := rand.NewSource(time.Now().UnixNano()) 
	// Create a random generator 
	rand := rand.New(source) 
	// Fill the token with random ASCII characters from 48 to 122 
	for i := range token { token[i] = byte(rand.Intn(75) + 48) } 
	// Return the token as a string 
	return string(token) 
}

// GameServer is a struct for game server 
type GameServer struct { 
	// Address is the server address 
	Address string 
	// Listener is the UDP listener 
	Listener net.PacketConn 
	// Sessions is the map of sessions with session ID as key and client address as value 
	Sessions map[uint32]net.Addr 
}

// NewGameServer creates a new game server 
func NewGameServer(address string) *GameServer { 
	// Create a new game server with the given address 
	server := &GameServer{ Address: address, } 
	// Initialize the map of sessions 
	server.Sessions = make(map[uint32]net.Addr) 
	// Return the server 
	return server 
}

// Start starts the game server 
func (s *GameServer) Start() error {
	// Create a UDP listener on the server address 
	listener, err := net.ListenPacket("udp", s.Address) 
	if err != nil { return err } 
	// Save the listener 
	s.Listener = listener 
	// Print a message 
	fmt.Println("Game server started on", s.Address) 
	// Accept packets in a loop 
	for { 
		// Create a buffer for reading data 
		buf := make([]byte, 36) 
		// Read data from the listener 
		n, addr, err := s.Listener.ReadFrom(buf) 
		if err != nil { 
			fmt.Println("Error reading data from", addr, ":", err)
			continue
		} 
		// Print a message 
		fmt.Println("Received packet from", addr) 
		// Handle the packet in a goroutine 
		go s.HandlePacket(buf[:n], addr) 
	}
}

// HandlePacket handles a packet 
func (s *GameServer) HandlePacket(data []byte, addr net.Addr) {
	// Parse the data as a token request packet 
	packet := s.ParseTokenRequestPacket(data) 
	if packet == nil { 
		fmt.Println("Invalid packet from", addr)
		return
	} 
	// Print a message 
	fmt.Println("Received token request from", addr, "with token", packet.Token) 
	// Check if the token is valid 
	if !s.ValidateToken(packet.Token) {
		fmt.Println("Invalid token from", addr)
		return
	} 
	// Generate a random session ID 
	session := s.GenerateSession() 
	// Save the session and the client address in the map 
	s.Sessions[session] = addr 
	// Create a token response packet with the session ID 
	response := &TokenResponsePacket{ Session: session, } 
	// Get the bytes of the response packet 
	data = response.GetBytes() 
	// Write the data to the client address 
	_, err := s.Listener.WriteTo(data, addr) 
	if err != nil {
		fmt.Println("Error writing data to", addr, ":", err)
		return
	} 
	// Print a message 
	fmt.Println("Sent token response to", addr, "with session", session)
}

// ParseTokenRequestPacket parses a byte slice as a token request packet 
func (s *GameServer) ParseTokenRequestPacket(data []byte) *TokenRequestPacket { 
	// Check if the data length is 36 
	if len(data) != 36 { return nil } 
	// Check if the packet type is 2000 
	if binary.LittleEndian.Uint16(data[2:4]) != uint16(TokenRequest) { return nil } 
	// Create a new token request packet 
	packet := &TokenRequestPacket{} 
	// Read the token as ASCII string 
	packet.Token = string(data[4:36]) 
	// Return the packet 
	return packet
}

// ValidateToken validates a token 
func (s *GameServer) ValidateToken(token string) bool {
	// TODO: Implement a proper validation logic using a database or a cache
	// For now, just return true for any token 
	return true
}

// GenerateSession generates a random session ID 
func (s *GameServer) GenerateSession() uint32 {
	// Create a random source 
	source := rand.NewSource(time.Now().UnixNano()) 
	// Create a random generator 
	rand := rand.New(source) 
	// Return a random uint32 
	return rand.Uint32()
}

func main() {
	// Create a new authorization server on port 5000 
	authServer := NewAuthServer(":5000") 
	// Start the authorization server in a goroutine 
	go authServer.Start() 
	// Create a new game server on port 8080 
	gameServer := NewGameServer(":8080") 
	// Start the game server
	gameServer.Start()
}