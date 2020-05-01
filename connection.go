package miio

import (
	"net"
	"time"
)

var maxBufferSize = 4096

func readResponse(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, maxBufferSize)
	i, err := readTimeout(conn, buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:i], nil
}

func readTimeout(conn net.Conn, buffer []byte) (int, error) {
	resultChan := make(chan int, 1)
	errChan := make(chan error, 1)

	go func() {
		err := conn.SetReadDeadline(deadline())
		if err != nil {
			errChan <- err
			return
		}
		n, err := conn.Read(buffer)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- n
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return 0, err
	}
}

var timeout = 2 * time.Second

func deadline() time.Time {
	return time.Now().Add(timeout)
}
