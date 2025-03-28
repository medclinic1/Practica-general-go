// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.

// Canal tiene que estar cifrado con SSL
// Usuario con hash y salt
// Comprobar si el usuario se sabe la contraseña
// Introducir en el cliente para que se pueda conectar con SSL
// Meter en el cliente el https
/*  En la fila 144 de la plantilla inicial se genera el token. para los token hay que generar una secuencia
aleatoria e impredecible y suficientemente largo para que no se pueda adivinar. La otra condición es que el token
tiene una fecha de caducidad. Hay que guardar el token y la fecha de expiración. El cliente lo maneja enviando
el token cada vez que quiere hacer una acción. Si no valida el token , el servidor tiene que mandar un mensaje de error. Generarlo
aleatorio, ponerle una fecha de caducidad y comparar el token con el guardado en el servidor con la fecha de caducidad.*/

package client

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"syscall"
	"time"

	"golang.org/x/term"
	"prac/pkg/api"
	"prac/pkg/ui"

	"strconv"

)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
}

// Token representa un token con una fecha de expiración.
type Token struct {
	Value     string
	ExpiresAt time.Time
}


/*// generateToken crea un token aleatorio y define su caducidad.
func generateToken() Token {
	// Crear un token aleatorio de 32 bytes
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		panic("Error generando token")
	}

	tokenValue := base64.StdEncoding.EncodeToString(tokenBytes)

	// Definir una duración del token (por ejemplo, 15 minutos)
	expiration := time.Now().Add(15 * time.Minute)

	return Token{
		Value:     tokenValue,
		ExpiresAt: expiration,
	}
}
	*/

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
				"Crear nuevo expediente",
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
				c.createExpediente()
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


// hashPassword genera un hash SHA-512 y lo convierte a Base64
func hashPassword(password string) string {
	hash := sha512.Sum512([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	fd := int(syscall.Stdin)
	bytePassword, err := term.ReadPassword(fd)
	if err != nil {
		fmt.Println("\nError al leer la contraseña.")
		return ""
	}
	fmt.Println() // Salto de línea después de la contraseña oculta
	return string(bytePassword)
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password := readPassword("Contraseña: ")
	hashedPassword := hashPassword(password) // Hashear antes de enviar

	nombre := ui.ReadInput("Nombre")
	apellidos := ui.ReadInput("Apellidos")
	especialidad := ui.ReadInput("Especialidad médica")
	hospital := ui.ReadInput("Hospital")
	userData := map[string]string{
		"nombre":       nombre,
		"apellidos":    apellidos,
		"especialidad": especialidad,
		"hospital":     hospital,
	}


	userDataJSON, _ := json.Marshal(userData)
	res := c.sendRequest(api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password:hashedPassword,
		Data:     string(userDataJSON),
	})
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	if res.Success {
		c.log.Println("Registro exitoso; intentando login automático...")
		loginRes := c.sendRequest(api.Request{
			Action:   api.ActionLogin,
			Username: username,
			Password: hashedPassword,
		})

		if loginRes.Success {
			c.currentUser = username
			c.authToken = res.Token
			fmt.Println("Login automático exitoso. Token guardado.")
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
		}
	}
}

var contraseña string

func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password := readPassword("Contraseña: ")
	contraseña = password
	hashedPassword := hashPassword(password)

	res := c.sendRequest(api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: hashedPassword,
	})

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
    for {
        ui.ClearScreen()
        fmt.Println("** Expedientes Médicos **")

        // Verificar sesión
        if c.currentUser == "" || c.authToken == "" {
            fmt.Println("Debes iniciar sesión primero")
            ui.ReadInput("\nPresione Enter para continuar...")
            return
        }

        // Obtener datos del servidor
        res := c.sendRequest(api.Request{
            Action:   api.ActionFetchData,
            Username: c.currentUser,
            Token:    c.authToken,
        })

        if !res.Success {
            fmt.Println("Error:", res.Message)
            ui.ReadInput("\nPresione Enter para continuar...")
            return
        }

        // Deserializar expedientes
        var expedientesJSON []string
        if err := json.Unmarshal([]byte(res.Data), &expedientesJSON); err != nil {
            fmt.Println("Error al deserializar lista de expedientes:", err)
            ui.ReadInput("\nPresione Enter para continuar...")
            return
        }

        // Mostrar todos los expedientes
        var expedientes []map[string]interface{}
        for _, expJSON := range expedientesJSON {
            var expediente map[string]interface{}
            if err := json.Unmarshal([]byte(expJSON), &expediente); err != nil {
                fmt.Printf("Error al deserializar expediente: %v\n", err)
                continue
            }
            expedientes = append(expedientes, expediente)
            
            fmt.Printf("\n=== Expediente ID: %v ===\n", expediente["id"])
            fmt.Printf("Fecha: %v\n", expediente["fecha_creacion"])

            datosEnc, ok := expediente["datos"].(string)
            if !ok {
                fmt.Println("(Resumen no disponible)")
                continue
            }

            datosMedicos := decryptData(datosEnc,contraseña)
            if datosMedicos == "" {
                fmt.Println("(Resumen no disponible)")
                continue
            }

            mostrarDatosMedicos(datosMedicos)
        }

        // Opciones principales
        fmt.Println("\nOpciones:")
        fmt.Println("1. Eliminar un expediente")
        fmt.Println("2. Actualizar un expediente")
        fmt.Println("3. Volver al menú principal")
        
        choice, err := strconv.Atoi(ui.ReadInput("Seleccione una opción"))
        if err != nil {
            fmt.Println("Opción no válida")
            ui.ReadInput("\nPresione Enter para continuar...")
            continue
        }

        switch choice {
        case 1: // Eliminar expediente
            if len(expedientes) == 0 {
                fmt.Println("No hay expedientes para eliminar")
                ui.ReadInput("\nPresione Enter para continuar...")
                continue
            }

            idStr := ui.ReadInput("\nIntroduzca el ID del expediente a eliminar")
            idEliminar, err := strconv.Atoi(idStr)
            if err != nil {
                fmt.Println("ID no válido")
                ui.ReadInput("\nPresione Enter para continuar...")
                continue
            }
            
            // Verificar que el ID existe
            existe := false
            for _, exp := range expedientes {
                if int(exp["id"].(float64)) == idEliminar {
                    existe = true
                    break
                }
            }

            if !existe {
                fmt.Printf("No existe un expediente con ID %d\n", idEliminar)
                ui.ReadInput("\nPresione Enter para continuar...")
                continue
            }

            // Confirmación
            fmt.Printf("\n¿Está seguro que desea eliminar el expediente %d?\n", idEliminar)
            fmt.Println("1. Confirmar eliminación")
            fmt.Println("2. Cancelar")
            
            confirmStr := ui.ReadInput("Seleccione una opción")
            confirmacion, err := strconv.Atoi(confirmStr)
            if err != nil || (confirmacion != 1 && confirmacion != 2) {
                fmt.Println("Opción no válida")
                ui.ReadInput("\nPresione Enter para continuar...")
                continue
            }
            
            if confirmacion == 1 {
                // Enviar solicitud de eliminación
                deleteRes := c.sendRequest(api.Request{
                    Action:   api.ActionEliminarData,
                    Username: c.currentUser,
                    Token:    c.authToken,
                    Data:     idStr, // Enviar como string
                })

                // Mostrar resultado de la operación
                if deleteRes.Success {
                    fmt.Printf("\nÉxito: %s\n", deleteRes.Message)
                } else {
                    fmt.Printf("\nError: %s\n", deleteRes.Message)
                }
                
                // Pausa para que el usuario vea el mensaje
                ui.ReadInput("\nPresione Enter para continuar...")
                
                // Salir del switch para refrescar la lista
                continue
            }

        case 2: // Actualizar expediente
            fmt.Println("Función de actualización no implementada aún")
            ui.ReadInput("\nPresione Enter para continuar...")

        case 3: // Volver
            return

        default:
            fmt.Println("Opción no válida")
            ui.ReadInput("\nPresione Enter para continuar...")
        }
    }
}

// Función auxiliar para mostrar datos (igual que antes)
func mostrarDatosMedicos(datos string) {
    var info struct {
        Nombre         string  `json:"nombre"`
        Apellidos     string  `json:"apellidos"`
        FechaNacimiento string `json:"fechaNacimiento"`
        SIP           float64 `json:"sip"`
        Sexo          string  `json:"sexo"`
        Observaciones string  `json:"observaciones"`
        Solicitud     string  `json:"solicitud"`
    }

    if err := json.Unmarshal([]byte(datos), &info); err != nil {
        fmt.Println("Error al procesar datos médicos:", err)
        return
    }

    fmt.Println("-------------------------------------------------")
    fmt.Printf("| %-15s | %-15s | %-15s |\n", "Nombre", "Apellidos", "Fecha Nac.")
    fmt.Println("-------------------------------------------------")
    fmt.Printf("| %-15s | %-15s | %-15s |\n", info.Nombre, info.Apellidos, info.FechaNacimiento)
    fmt.Println("-------------------------------------------------")
    fmt.Printf("SIP: %.0f | Sexo: %s\n", info.SIP, info.Sexo)
    fmt.Println("Observaciones:", info.Observaciones)
    fmt.Println("Solicitud:", info.Solicitud)
    fmt.Println("-------------------------------------------------")
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) createExpediente() {
	ui.ClearScreen()
	fmt.Println("** Crear nuevo expediente **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	
	nombre := ui.ReadInput("Nombre paciente")
	apellidos := ui.ReadInput("Apellidos paciente")
	fechaNacimiento := ui.ReadInput("Fecha de nacimiento (YYYY-MM-DD)")
	sip := ui.ReadInt("SIP")
	sexo := ui.ReadInput("Sexo (M/F)")
	observaciones := ui.ReadMultiline("Observaciones")
	solicitud := ui.ReadMultiline("Solicitud")

	expedienteData := map[string]interface{}{
		"nombre":          nombre,
		"apellidos":       apellidos,
		"fechaNacimiento": fechaNacimiento,
		"sip":             sip,
		"sexo":            sexo,
		"observaciones":   observaciones,
		"solicitud":       solicitud,
	}

	fmt.Println("1. Subir expediente")
	fmt.Println("2. Borrar expediente")
	choice := ui.ReadInt("Seleccione una opción")

	if choice == 1 {
		dataJSON, _ := json.Marshal(expedienteData)
		encryptedData := encryptData(string(dataJSON), contraseña)
		res := c.sendRequest(api.Request{
			Action:   api.ActionUpdateData,
			Username: c.currentUser,
			Token:    c.authToken,
			Data:     encryptedData,
		})
		
		if res.Success {

			fmt.Println("Éxito:", res.Success)
		    fmt.Println("Mensaje:", res.Message)
		}
	} else {
		fmt.Println("Expediente borrado. Volviendo al menú principal...")
	}
}

func encryptData(text, password string) string {
	// Generar clave desde la contraseña del usuario
	key := obtenerSHA256(password)
	
	// Crear IV aleatorio
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		log.Fatalf("Error generando IV: %v", err)
	}
	

	// Comprimir datos
	var buffer bytes.Buffer
	compressor := zlib.NewWriter(&buffer)
	compressor.Write([]byte(text))
	compressor.Close()

	// Cifrar datos usando modo CTR
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creando el cifrador AES: %v", err)
	}
	stream := cipher.NewCTR(block, iv)

	encrypted := make([]byte, buffer.Len())
	stream.XORKeyStream(encrypted, buffer.Bytes())

	// Concatenar IV + datos cifrados
	finalData := append(iv, encrypted...)

	// Codificar en base64 para evitar pérdida de datos
	encoded := base64.StdEncoding.EncodeToString(finalData)
	fmt.Printf("[DEBUG] Datos cifrados en base64: %s\n", encoded)

	return encoded
}

func decryptData(encryptedText, password string) string {
	// Generar clave desde la contraseña del usuario
	key := obtenerSHA256(password)
	

	// Decodificar desde base64
	decoded, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		fmt.Println("Error decodificando base64:", err)
		return ""
	}
	

	// Verificar que los datos cifrados incluyen al menos 16 bytes para el IV
	if len(decoded) < 16 {
		fmt.Println("Error: Datos cifrados demasiado cortos.")
		return ""
	}

	// Extraer IV (primeros 16 bytes)
	iv := decoded[:16]
	encryptedData := decoded[16:]

	// Descifrar datos usando modo CTR
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creando el cifrador AES: %v", err)
	}
	stream := cipher.NewCTR(block, iv)

	decrypted := make([]byte, len(encryptedData))
	stream.XORKeyStream(decrypted, encryptedData)


	// Descomprimir datos
	buffer := bytes.NewReader(decrypted)
	reader, err := zlib.NewReader(buffer)
	if err != nil {
		fmt.Println("Error al descomprimir los datos:", err)
		return ""
	}
	decompressed, err := io.ReadAll(reader)
	reader.Close()

	if err != nil {
		fmt.Println("Error al leer los datos descomprimidos:", err)
		return ""
	}

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
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */

	/*//Verificar si el token sigue siendo válido
	if c.authToken == "" {
		fmt.Println("Error: No hay token disponible.")
		return api.Response{Success: false, Message: "No autenticado"}
	}
		*/

	// Adjuntar el token en la solicitud
	//req.Token = c.authToken

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}


	jsonData, _ := json.Marshal(req)
	resp, err := client.Post("https://localhost:8080/api", "application/json", bytes.NewBuffer(jsonData))

	
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
