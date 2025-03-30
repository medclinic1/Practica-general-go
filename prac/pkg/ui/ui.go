// El paquete ui proporciona un conjunto de funciones sencillas
// para la interacción con el usuario mediante terminal
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PrintMenu muestra un menú y solicita al usuario que seleccione una opción.
func PrintMenu(title string, options []string) int {
	fmt.Print(title, "\n\n")
	for i, option := range options {
		fmt.Printf("%d. %s\n", i+1, option)
	}
	fmt.Print("\nSelecciona una opción: ")

	var choice int
	for {
		_, err := fmt.Scanln(&choice)
		if err == nil && choice >= 1 && choice <= len(options) {
			break
		}
		fmt.Println("Opción no válida, inténtalo de nuevo.")
		fmt.Print("Selecciona una opción: ")
	}
	return choice
}

// ReadInput solicita un texto al usuario y lo devuelve como string.
func ReadInput(prompt string) string {
	fmt.Print(prompt + ": ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

// Confirm solicita una confirmación Sí/No al usuario.
func Confirm(message string) bool {
	for {
		fmt.Print(message + " (S/N): ")
		var response string
		fmt.Scanln(&response)
		response = strings.ToUpper(strings.TrimSpace(response))
		if response == "S" {
			return true
		} else if response == "N" {
			return false
		}
		fmt.Println("Respuesta no válida, introduce S o N.")
	}
}

// ClearScreen limpia la pantalla de la terminal.
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// Pause muestra un mensaje y espera a que el usuario presione Enter.
func Pause(prompt string) {
	fmt.Println(prompt)
	bufio.NewScanner(os.Stdin).Scan()
}

// ReadInt solicita al usuario un entero y valida la entrada.
func ReadInt(prompt string) int {
	for {
		fmt.Print(prompt + ": ")
		var value int
		_, err := fmt.Scanln(&value)
		if err == nil {
			return value
		}
		fmt.Println("Valor no válido, introduce un número entero.")
		bufio.NewScanner(os.Stdin).Scan()
	}
}

// ReadFloat solicita al usuario un número real y valida la entrada.
func ReadFloat(prompt string) float64 {
	for {
		fmt.Print(prompt + ": ")
		var value float64
		_, err := fmt.Scanln(&value)
		if err == nil {
			return value
		}
		fmt.Println("Valor no válido, introduce un número real.")
		bufio.NewScanner(os.Stdin).Scan()
	}
}

// ReadMultiline lee varias líneas hasta que el usuario introduzca línea vacía.
func ReadMultiline(prompt string) string {
	fmt.Println(prompt + " (deja una línea en blanco para terminar):")
	scanner := bufio.NewScanner(os.Stdin)
	var lines []string
	for {
		scanner.Scan()
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// PrintProgressBar muestra una barra de progreso en la terminal.
func PrintProgressBar(progress, total int, width int) {
	percent := float64(progress) / float64(total) * 100.0
	filled := int(float64(width) * (float64(progress) / float64(total)))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	fmt.Printf("\r[%s] %.2f%%", bar, percent)
	if progress == total {
		fmt.Println()
	}
}

// ReadInputWithDefault muestra un prompt y permite al usuario introducir un valor o mantener el predeterminado
func ReadInputWithDefault(prompt, defaultValue string) string {
    fmt.Printf("%s [%s]: ", prompt, defaultValue)
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadString('\n')
    input = strings.TrimSpace(input)
    
    if input == "" {
        return defaultValue
    }
    return input
}

// ReadIntWithDefault similar a ReadInputWithDefault pero para enteros
func ReadIntWithDefault(prompt, defaultValue string) int {
    for {
        input := ReadInputWithDefault(prompt, defaultValue)
        val, err := strconv.Atoi(input)
        if err == nil {
            return val
        }
        fmt.Println("Por favor, introduzca un número válido")
    }
}

// ReadMultilineWithDefault para campos multilínea
func ReadMultilineWithDefault(prompt, defaultValue string) string {
    fmt.Printf("%s (actual:)\n%s\n", prompt, defaultValue)
    fmt.Println("Introduzca el nuevo valor (multilínea, termine con una línea que contenga sólo '.'):")
    
    var lines []string
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        if line == "." {
            break
        }
        lines = append(lines, line)
    }
    
    if len(lines) == 0 {
        return defaultValue
    }
    return strings.Join(lines, "\n")
}


