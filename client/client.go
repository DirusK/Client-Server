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
	fmt.Println("~~~КЛИЕНТ~~~")
	var (
		password string
		adr string
	)

	fmt.Print("Введите Ip-адрес для подключения: ")
	fmt.Scanln(&adr)

	//adr := "127.0.0.1:4545"
	tokenClient := token{Adress: adr}
	conn, err := net.Dial("tcp", tokenClient.Adress)
	if err != nil {
		fmt.Println("Dial error: ", err)
		return
	} else {
		fmt.Println("Подключение к серверу прошло успешно")
	}
	defer conn.Close()

	fmt.Print("Введите пароль: ")
	fmt.Scanln(&password)
	fmt.Println("Сформируем случайное число Ra...")
	tokenClient.Ra, err = GenerateRandomBytes(32)
	if err != nil {
		fmt.Println("Generate bytes error: ", err)
		return
	}
	fmt.Printf("Ra: %x\n", tokenClient.Ra)

	input := make([]byte, (1024 * 4))
	n, err := conn.Read(input)
	if n == 0 || err != nil {
		fmt.Println("Read error:", err)
		return
	}
	tokenClient.Rb = input[0:n]
	fmt.Println("Получено число Rb от сервера")
	fmt.Printf("Rb: %x\n", tokenClient.Rb)

	var msg []byte
	msg = append(msg, tokenClient.Ra...)
	msg = append(msg, tokenClient.Rb...)
	msg = append(msg, []byte(password)...)
	msg = append(msg, []byte(tokenClient.Adress)...)
	fmt.Println("Сформируем подпись от пароля, случайных чисел Ra,Rb и идентификатора сервера...")
	hash := sha256.Sum256(msg)

	fmt.Println("**************************")
	fmt.Printf("SHA-256 Hash: %x\n", hash)
	curve := elliptic.P256().Params()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tokenClient.Sign, err = ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("ECDSA Signature: %x\n", tokenClient.Sign)
	fmt.Println("**************************")

	fmt.Println("\nПараметры эллиптической кривой")
	fmt.Println("**************************")
	fmt.Printf("Порядок поля: %d\n", curve.P)
	fmt.Printf("Порядок базовой точки: %d\n", curve.N)
	fmt.Printf("Константа B: %d\n", curve.B)
	fmt.Println("Базовая точка G")
	fmt.Printf("X: %d\n", curve.Gx)
	fmt.Printf("Y: %d\n", curve.Gy)
	fmt.Println("Каноническое имя кривой: ", curve.Name)
	fmt.Println("**************************")

	fmt.Println("\nСформированный закрытый ключ:")
	fmt.Println("D: ", privateKey.D)

	fmt.Println("\nСформированный публичный ключ:")
	fmt.Println("X: ", privateKey.PublicKey.X)
	fmt.Println("Y: ", privateKey.PublicKey.Y)

	// кодируем открытый ключ и вычисленный токен
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	tok, err := json.Marshal(tokenClient)
	fmt.Println("Отправляем открытый ключ и маркер серверу...")
	conn.Write(publicKey)
	conn.Write(tok)
	n, err = conn.Read(input)
	if n == 0 || err != nil {
		fmt.Println("Read error:", err)
		return
	}
	fmt.Println(string(input[0:n]))
	fmt.Println("Конец работы клиента. Нажмите ENTER для выхода из программы...")
	fmt.Scanln()
}
