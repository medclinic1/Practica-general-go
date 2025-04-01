/*
'prac' es una base para el desarrollo de prácticas en clase con Go.

se puede compilar con "go build" en el directorio donde resida main.go

versión: 1.0
Cambio

curso: 			**rellenar**
asignatura: 	**antes de**
estudiantes: 	**entregar**
*/

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"golang.org/x/term"
	"prac/pkg/client"
	"prac/pkg/server"
	"prac/pkg/ui"
)

var masterKey string

func readMasterKey() string {
	fmt.Print("Ingrese la clave maestra: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal("Error al leer la clave maestra")
	}
	fmt.Println()
	return string(bytePassword)
}

func main() {

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	// AES-CTR con clave de 128,256... bits y con un nonce
	log := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// Solicitar la clave maestra al inicio
	masterKey = readMasterKey()

	log.Println("Clave maestra establecida.")

	log.Println("Iniciando servidor...")
	go func() {
		if err := server.Run(masterKey); err != nil {
			log.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	// Esperamos un tiempo prudencial a que arranque el servidor.
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Inicia cliente.
	log.Println("Iniciando cliente...")
	client.Run()
}
