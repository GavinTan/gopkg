package tools

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func FormatBytes(size float64) string {
	unit := [...]string{"B", "KB", "MB", "GB", "TB"}

	for _, v := range unit {
		if size < 1024 {
			return fmt.Sprintf("%1.0f %s", size, v)
		}

		size /= 1024

	}
	return fmt.Sprintf("%1.0f", size)
}

func IndexOf(arr []string, e string) int {
	for k, v := range arr {
		if e == v {
			return k
		}
	}
	return -1
}

func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func GetHostIP() (ip string) {
	defer func() {
		if r := recover(); r != nil {
			ip = "127.0.0.1"
		}
	}()

	conn, _ := net.Dial("udp", "8.8.8.8:53")
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip = strings.Split(localAddr.String(), ":")[0]

	return ip
}

func RandomPort() string {
	rand.Seed(time.Now().UnixNano())
	port := rand.Intn(20000-10000) + 10000
	return strconv.Itoa(port)
}
