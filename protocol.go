package miio

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
)

func Call(ip net.IP, token *[16]byte, methodName string, args ...interface{}) ([]byte, error) {
	type request struct {
		RequestId  int16         `json:"id"`
		MethodName string        `json:"method"`
		Args       []interface{} `json:"params"`
	}
	data, err := json.Marshal(request{
		RequestId:  1,
		MethodName: methodName,
		Args:       args,
	})
	if err != nil {
		return nil, err
	}
	return handshakeAndRequest(ip, token, data)
}

var defaultPort = 54321

func handshakeAndRequest(ip net.IP, token *[16]byte, data []byte) ([]byte, error) {
	udpAddr := net.UDPAddr{IP: ip, Port: defaultPort}
	conn, err := net.DialUDP("udp", nil, &udpAddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()
	handshake, err := doHandshake(conn)
	if err != nil {
		return nil, err
	}
	return doCall(conn, token, handshake, data)
}

type handshake struct {
	DeviceId    uint32
	ServerStamp uint32
}

func doHandshake(conn net.Conn) (*handshake, error) {
	_, err := conn.Write(bHandshakeRequest)
	if err != nil {
		return nil, err
	}
	response, err := readResponse(conn)
	if err != nil {
		return nil, err
	}
	return parseHandshakeResponse(response)
}

var bHandshakeRequest = []byte{
	0x21, 0x31, 0x00, 0x20, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

func (r *handshake) String() string {
	return fmt.Sprintf("handshake{DeviceId: %d, ServerStamp: %d}", r.DeviceId, r.ServerStamp)
}

func parseHandshakeResponse(response []byte) (*handshake, error) {
	handshakeLen := len(response)
	if handshakeLen != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", handshakeLen)
	}
	deviceId := binary.BigEndian.Uint32(response[8:])
	serverStamp := binary.BigEndian.Uint32(response[12:])
	return &handshake{deviceId, serverStamp}, nil
}

func doCall(conn net.Conn, token *[16]byte, handshake *handshake, data []byte) ([]byte, error) {
	keys := deviceKeysFromToken(token)
	encrypted := keys.encrypt(data)
	header := prepareRequestHeader(token, handshake, encrypted)
	request := append(header[:], encrypted...)

	_, err := conn.Write(request)
	if err != nil {
		return nil, err
	}
	response, err := readResponse(conn)
	if err != nil {
		return nil, err
	}
	// todo validate response
	return decrypt(keys, response[32:]), nil
}

func prepareRequestHeader(token *[16]byte, handshake *handshake, requestBody []byte) [32]byte {
	header := [32]byte{0x21, 0x31}
	binary.BigEndian.PutUint16(header[2:], uint16(32+len(requestBody)))
	binary.BigEndian.PutUint32(header[8:], handshake.DeviceId)
	binary.BigEndian.PutUint32(header[12:], handshake.ServerStamp)
	checksum := md5(header[:16], token[:], requestBody)
	copy(header[16:], checksum[:])
	return header
}
