package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
)

type token struct {
	Ra     []byte
	Rb     []byte
	Adress string // идентификатор
	Sign   []byte
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}
func main() {
	fmt.Println("~~~СЕРВЕР~~~")
	password := "admin"
	listener, err := net.Listen("tcp", ":4545")
	if err != nil {
		fmt.Println("Listen error: ", err)
		return
	}
	defer listener.Close()
	conn, err := listener.Accept() // Принимаем входящее соединение
	if err != nil {
		fmt.Println("Accept error: ", err)
		return
	}
	fmt.Println("Получено входящее подключение от ", conn.RemoteAddr())
	defer conn.Close()
	fmt.Println("Генерируем случайное число Rb и отправляем клиенту..")
	Rb, err := GenerateRandomBytes(32) // Формирование рандомного числа
	if err != nil {
		fmt.Println("Generate bytes error: ", err)
		return
	}
	fmt.Printf("Rb: %x\n", Rb)
	if n, err := conn.Write(Rb); n == 0 || err != nil { // Передача рандомного числа клиенту
		fmt.Println(err)
		return
	}
	input := make([]byte, (1024 * 4))
	n, err := conn.Read(input)
	if n == 0 || err != nil {
		fmt.Println("Read error:", err)
		return
	}
	var pub ecdsa.PublicKey
	pub.Curve = elliptic.P256()
	pub.X, pub.Y = elliptic.Unmarshal(elliptic.P256(), input[:n])
	fmt.Println("Получен открытый ключ со стороны клиента")
	fmt.Println("X: ", pub.X)
	fmt.Println("Y: ", pub.Y)

	n, err = conn.Read(input)
	if n == 0 || err != nil {
		fmt.Println("Read error:", err)
		return
	}
	var tokenServer token
	err = json.Unmarshal(input[0:n], &tokenServer)
	fmt.Printf("Получен токен клиента\nRa: %x\nRb: %x\nAdress: %s\nSignature: %x\n", tokenServer.Ra, tokenServer.Rb, tokenServer.Adress, tokenServer.Sign)

	fmt.Println("Проверим подпись клиента...")
	var msg []byte
	msg = append(msg, tokenServer.Ra...)
	msg = append(msg, Rb...)
	msg = append(msg, []byte(password)...)
	msg = append(msg, []byte(tokenServer.Adress)...)
	hash := sha256.Sum256(msg)
	valid := ecdsa.VerifyASN1(&pub, hash[:], tokenServer.Sign)
	if valid {
		fmt.Println("Подпись подтверждена. Пользователь аутентифицирован!")
		conn.Write([]byte("Вы прошли процесс аутентификации!"))
	} else {
		fmt.Println("Подпись не подтверждена!")
		conn.Write([]byte("Вы НЕ прошли процесс аутентификации!"))
	}
	fmt.Println("Конец работы сервера. Нажмите ENTER для выхода из программы...")
	fmt.Scanln()
}
