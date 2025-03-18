// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.

// Canal tiene que estar cifrado con SSL
// Usuario con hash y salt
// Comprobar si el usuario se sabe la contraseña
// Introducir en el cliente para que se pueda conectar con SSL
// Meter en el cliente el https

package client

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"prac/pkg/api"
	"prac/pkg/ui"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
}

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
	}
	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Si NO hay usuario logueado, se muestran ciertas opciones;
// si SÍ hay usuario logueado, se muestran otras.
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario logueado, si lo hubiera.
		var title string
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// Usuario logueado: Ver datos, Actualizar datos, Logout, Salir
			options = []string{
				"Ver datos",
				"Actualizar datos",
				"Cerrar sesión",
				"Salir",
			}
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.logoutUser()
			case 4:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
	})

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		c.log.Println("Registro exitoso; intentando login automático...")

		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: password,
		})
		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
			fmt.Println("Login automático exitoso. Token guardado.")
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
		}
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := ui.ReadInput("Contraseña")

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{
		Action:   api.ActionFetchData,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	if !res.Success {
		fmt.Println("Error al obtener datos:", res.Message)
		return
	}

	// Antes de desencriptar
	fmt.Println("Datos encriptados recibidos:", res.Data)

	// Desencriptar los datos recibidos
	decryptedData := decryptData(res.Data)
	fmt.Println("Datos encriptados recibidos:", res.Data)

	// Verificar el resultado de la desencriptación
	fmt.Println("Datos desencriptados:", decryptedData)

	// Intentar decodificar JSON
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &data); err != nil {
		fmt.Println("Error al procesar los datos:", err)
		return
	}

	// Mostrar los datos en formato de tabla
	fmt.Println("\n-------------------------------------------------")
	fmt.Printf("| %-15s | %-15s | %-15s | %-10s | %-4s | %-16s | %-16s |\n",
		"Nombre", "Apellidos", "Fecha Nac.", "SIP", "Sexo", "Observaciones", "Solicitud")
	fmt.Println("-------------------------------------------------")
	fmt.Printf("| %-15s | %-15s | %-15s | %-10d | %-4s | %-16s | %-16s |",
		data["nombre"], data["apellidos"], data["fechaNacimiento"], int(data["sip"].(float64)), data["sexo"], data["observaciones"], data["solicitud"])
	fmt.Println()
	fmt.Println("-------------------------------------------------")

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		fmt.Println("Tus datos:", res.Data)
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva información del paciente
	nombre := ui.ReadInput("Nombre paciente")
	apellidos := ui.ReadInput("Apellidos paciente")
	fechaNacimiento := ui.ReadInput("Fecha de nacimiento (YYYY-MM-DD)")
	sip := ui.ReadInt("SIP")
	sexo := ui.ReadInput("Sexo (M/F)")
	observaciones := ui.ReadMultiline("Observaciones")
	solicitud := ui.ReadMultiline("Solicitud")

	// Construimos la estructura de datos para enviar al servidor
	pacienteData := map[string]interface{}{
		"nombre":          nombre,
		"apellidos":       apellidos,
		"fechaNacimiento": fechaNacimiento,
		"sip":             sip,
		"sexo":            sexo,
		"observaciones":   observaciones,
		"solicitud":       solicitud,
	}

	dataJSON, _ := json.Marshal(pacienteData)
	encryptedData := encryptData(string(dataJSON))
	fmt.Println("Datos encriptados enviados:", encryptedData)

	res := c.sendRequest(api.Request{
		Action:   api.ActionUpdateData,
		Username: c.currentUser,
		Token:    c.authToken,
		Data:     encryptedData,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

}

// encryptData cifra los datos con AES-CTR y los comprime.
func encryptData(text string) string {
	key := obtenerSHA256("ClaveSegura")
	iv := obtenerSHA256("VectorInicial")[:16]

	// Comprimir datos
	var buffer bytes.Buffer
	compressor := zlib.NewWriter(&buffer)
	compressor.Write([]byte(text))
	compressor.Close()

	// Cifrar datos
	cipherBlock, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(cipherBlock, iv)

	encrypted := make([]byte, buffer.Len())
	stream.XORKeyStream(encrypted, buffer.Bytes())

	// Codificar en base64 para evitar pérdida de datos
	return base64.StdEncoding.EncodeToString(encrypted)
}

// decryptData descifra los datos con AES-CTR y los descomprime.
func decryptData(encryptedText string) string {
	key := obtenerSHA256("ClaveSegura")
	iv := obtenerSHA256("VectorInicial")[:16]

	// Decodificar desde base64
	decoded, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		fmt.Println("Error decodificando base64:", err)
		return ""
	}

	// Descifrar datos
	cipherBlock, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(cipherBlock, iv)

	decrypted := make([]byte, len(decoded))
	stream.XORKeyStream(decrypted, decoded)

	// Descomprimir datos
	buffer := bytes.NewReader(decrypted)
	reader, _ := zlib.NewReader(buffer)
	decompressed, _ := io.ReadAll(reader)
	reader.Close()

	return string(decompressed)
}

// obtenerSHA256 genera un hash SHA-256 de la clave
func obtenerSHA256(text string) []byte {
	h := sha256.New()
	h.Write([]byte(text))
	return h.Sum(nil)
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{
		Action:   api.ActionLogout,
		Username: c.currentUser,
		Token:    c.authToken,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
	}
}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request) api.Response {
	jsonData, _ := json.Marshal(req)
	resp, err := http.Post("http://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response
	body, _ := io.ReadAll(resp.Body)
	var res api.Response
	_ = json.Unmarshal(body, &res)
	return res
}
