// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"prac/pkg/api"
	"prac/pkg/store"

	"strconv"

	"golang.org/x/crypto/scrypt"
	
)

// Token representa un token con una fecha de expiración.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

func cifrarString(textoEnClaro string, key []byte, iv []byte) (string, error) {
	lectorTextoEnClaro := strings.NewReader(textoEnClaro)

	var buffer bytes.Buffer

	escritorConCifrado := cipher.StreamWriter{}
	var err error
	escritorConCifrado.S, err = obtenerAESconCTR(key, iv)
	if err != nil {
		return "", err
	}
	escritorConCifrado.W = &buffer

	escritorConCompresionyCifrado := zlib.NewWriter(escritorConCifrado)

	_, err = io.Copy(escritorConCompresionyCifrado, lectorTextoEnClaro)
	if err != nil {
		return "", err
	}

	escritorConCompresionyCifrado.Close()

	// Return the base64 encoded bytes directly
	//return []byte(base64.StdEncoding.EncodeToString(buffer.Bytes())), nil
	return encode64(buffer.Bytes()), nil

}

/*
func descifrarString(encryptedData string, key []byte, iv []byte) (string, error) {
	lectorTextoCifrado := strings.NewReader(encryptedData)

	var bufferDeBytesParaDescifraryDescomprimir bytes.Buffer

	var lectorConDescifrado cipher.StreamReader
	var err error
	lectorConDescifrado.S, err = obtenerAESconCTR(key, iv)
	if err != nil {
		return "", err
	}
	lectorConDescifrado.R = lectorTextoCifrado

	lectorConDescifradoDescompresion, err := zlib.NewReader(lectorConDescifrado)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(&bufferDeBytesParaDescifraryDescomprimir, lectorConDescifradoDescompresion)
	if err != nil {
		return "", err
	}

	lectorConDescifradoDescompresion.Close()
	textoEnClaroDescifrado := bufferDeBytesParaDescifraryDescomprimir.String()
	decoded, err := base64.StdEncoding.DecodeString(textoEnClaroDescifrado)
	return string(decoded), nil
}

*/

func descifrarString(encryptedData string, key []byte, iv []byte) (string, error) {
	// Decode the base64 encoded string
	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	lectorTextoCifrado := bytes.NewReader(decodedData)

	var bufferDeBytesParaDescifraryDescomprimir bytes.Buffer

	var lectorConDescifrado cipher.StreamReader
	lectorConDescifrado.S, err = obtenerAESconCTR(key, iv)
	if err != nil {
		return "", err
	}
	lectorConDescifrado.R = lectorTextoCifrado

	lectorConDescifradoDescompresion, err := zlib.NewReader(lectorConDescifrado)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(&bufferDeBytesParaDescifraryDescomprimir, lectorConDescifradoDescompresion)
	if err != nil {
		return "", err
	}

	lectorConDescifradoDescompresion.Close()
	return bufferDeBytesParaDescifraryDescomprimir.String(), nil
}

func obtenerAESconCTR(key []byte, iv []byte) (cipher.Stream, error) {
	//Si la clave no es de 128 o 256 bits => Error
	if !(len(key) == 16 || len(key) == 32) {
		return nil, errors.New("la clave no es de 128 o 256 bits")
	}

	CifradorDeUnBloque, err := aes.NewCipher(key)
	check(err)
	CifradorVariosBloquesConCTR := cipher.NewCTR(CifradorDeUnBloque, iv[:16])
	return CifradorVariosBloquesConCTR, nil
}

func obtenerSHA256(Clave string) []byte {
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(Clave))
	check(err)
	retorno := h.Sum(nil)
	return retorno
}

// server encapsula el estado de nuestro servidor
type server struct {
	db           store.Store // base de datos
	log          *log.Logger // logger para mensajes de error e información
	tokenCounter int64       // contador para generar tokens
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run(clavemaestra string) error {

	key := obtenerSHA256(clavemaestra)
	err := os.WriteFile("key.txt", []byte(key), 0755)
	if err != nil {
		fmt.Printf("unable to write file: %v", err)
	}

	//El iv debe ser diferente, generado en función del nombre del usuario cada vez que se inicia el servidor
	//Esto hay que cambiarlo
	iv := obtenerSHA256("<inicializar>")
	err2 := os.WriteFile("iv.txt", []byte(iv), 0755)
	if err2 != nil {
		fmt.Printf("unable to write file: %v", err2)
	}
	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:  db,
		log: log.New(os.Stdout, "[srv] ", log.LstdFlags),
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	//err = http.ListenAndServe(":8080", mux)

	// Para generar certificados autofirmados con openssl usar:
	// openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=ES/ST=Alicante/L=Alicante/O=UA/OU=Org/CN=www.ua.com"
	err = http.ListenAndServeTLS(":8080", "iv.pem", "key.pem", mux)

	return err
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	// es necesario parsear el formulario
	r.ParseForm()
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}

	// Despacho según la acción solicitada
	var res api.Response
	switch req.Action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		res = s.fetchData(req)
	case api.ActionUpdateData:
		res = s.updateData(req)
	case api.ActionLogout:
		res = s.logoutUser(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// generateToken crea un token único incrementando un contador interno (inseguro)
func (s *server) generateToken() (string, int64) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		panic("Error generando token")
	}
	timestamp := time.Now().Unix() // Current Unix timestamp
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	return token, timestamp
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
//var hsh []byte

func (s *server) registerUser(req api.Request) api.Response {
	// Validación básica
	if req.Username == "" || len(req.Password) == 0 {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Salt y Hash
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return api.Response{Success: false, Message: "Error al generar salt"}
	}

	hashedPassword, err := scrypt.Key([]byte(req.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		return api.Response{Success: false, Message: "Error al hashear contraseña"}
	}

	// Se separan con ':'
	saltAndHash := fmt.Sprintf("%s:%s", encode64(salt), encode64(hashedPassword))

	// Almacenamos el salt y el hash en el namespace 'auth' (clave=nombre, valor=salt:hash)
	if err := s.db.Put("auth", []byte(req.Username), []byte(saltAndHash)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Creamos una entrada vacía para los datos en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	// Basic validation
	if req.Username == "" || len(req.Password) == 0 {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Retrieve stored credentials
	storedPass, err := s.db.Get("auth", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	parts := strings.Split(string(storedPass), ":")
	if len(parts) != 2 {
		return api.Response{Success: false, Message: "Formato de credenciales inválido"}
	}
	salt := decode64(parts[0])
	storedHash := decode64(parts[1])
	hashedPassword, err := scrypt.Key([]byte(req.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		return api.Response{Success: false, Message: "Error al hashear contraseña"}
	}

	// Comparar
	if !bytes.Equal(hashedPassword, storedHash) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Token
	token, timestamp := s.generateToken()
	sessionData := fmt.Sprintf("%s:%d", token, timestamp)

	// Store the token and timestamp in 'sessions'
	if err := s.db.Put("sessions", []byte(req.Username), []byte(sessionData)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: token}
}

// fetchData verifica el token y retorna todos los expedientes médicos desencriptados
func (s *server) fetchData(req api.Request) api.Response {
    //log.Println("[fetchData] Iniciando función para usuario:", req.Username)
    
    // Leer key e iv del servidor
    key, err := os.ReadFile("key.txt")
    if err != nil {
        log.Printf("[ERROR] Error al leer key.txt: %v\n", err)
        return api.Response{Success: false, Message: "Error al leer clave de encriptación"}
    }

    iv, err := os.ReadFile("iv.txt")
    if err != nil {
        log.Printf("[ERROR] Error al leer iv.txt: %v\n", err)
        return api.Response{Success: false, Message: "Error al leer vector de inicialización"}
    }

    // Validar credenciales
    if req.Username == "" || req.Token == "" {
        return api.Response{Success: false, Message: "Faltan credenciales"}
    }
    if !s.isTokenValid(req.Username, req.Token) {
        return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
    }

     // Obtener datos de la base de datos
    encryptedData, err := s.db.Get("userdata", []byte(req.Username))
    if err != nil {
        log.Printf("[ERROR] Error al obtener datos: %v\n", err)
        return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
    }

    if len(encryptedData) == 0 {
        log.Println("[fetchData] No hay expedientes para este usuario")
        return api.Response{
            Success: true,
            Message: "El usuario no tiene expedientes médicos",
            Data:    "[]",
        }
    }

    // Debug: Ver formato de los datos almacenados
    log.Printf("[DEBUG] Primeros bytes de datos almacenados: %x\n", encryptedData[:32])
    log.Printf("[DEBUG] Datos como string: %s\n", string(encryptedData))

    // Intentar descifrar (2 enfoques)
    var decryptedData string
    var decryptionError error
    
    // Enfoque 1: Asumir que los datos están en base64
    decryptedData, decryptionError = descifrarString(string(encryptedData), key, iv)
    if decryptionError != nil {
        log.Printf("[WARN] Intento 1 de descifrado falló: %v\n", decryptionError)
        
        // Enfoque 2: Asumir que los datos son binarios puros
        decryptedData, decryptionError = descifrarBytes(encryptedData, key, iv)
        if decryptionError != nil {
            log.Printf("[ERROR] Intento 2 de descifrado falló: %v\n", decryptionError)
            return api.Response{
                Success: false,
                Message: "Error al descifrar datos del usuario",
            }
        }
        log.Println("[fetchData] Descifrado exitoso (enfoque binario)")
    } else {
        log.Println("[fetchData] Descifrado exitoso (enfoque base64)")
    }

    // Verificar si es JSON válido
    if !json.Valid([]byte(decryptedData)) {
        log.Printf("[ERROR] Datos descifrados no son JSON válido: %s\n", decryptedData)
        return api.Response{
            Success: false,
            Message: "Los datos almacenados no tienen un formato válido",
        }
    }

    return api.Response{
        Success: true,
        Message: "Expedientes médicos de " + req.Username,
        Data:    decryptedData,
    }
}

// Función auxiliar para descifrado binario
func descifrarBytes(ciphertext, key, iv []byte) (string, error) {
    // Implementa tu lógica de descifrado para datos binarios
    // Esto depende de tu implementación específica de cifrado
    // Ejemplo genérico:
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(ciphertext, ciphertext)

    // Eliminar padding si es necesario
    padding := int(ciphertext[len(ciphertext)-1])
    if padding > aes.BlockSize || padding <= 0 {
        return "", fmt.Errorf("invalid padding")
    }

    return string(ciphertext[:len(ciphertext)-padding]), nil
}
// updateData maneja la creación de nuevos expedientes médicos en 'userdata' con logs de depuración
func (s *server) updateData(req api.Request) api.Response {
    log.Println("[updateData] Iniciando función")
    log.Printf("[updateData] Usuario: %s, Token: %s\n", req.Username, req.Token)
    log.Printf("[updateData] Datos recibidos: %s\n", req.Data)

    // Leer key e iv para el servidor (segunda capa de encriptación)
    key, err := os.ReadFile("key.txt")
    if err != nil {
        log.Printf("[ERROR] No se pudo leer key.txt: %v\n", err)
        return api.Response{Success: false, Message: "Error al leer clave de encriptación"}
    }

    iv, err := os.ReadFile("iv.txt")
    if err != nil {
        log.Printf("[ERROR] No se pudo leer iv.txt: %v\n", err)
        return api.Response{Success: false, Message: "Error al leer vector de inicialización"}
    }

    // Validar credenciales
    if req.Username == "" || req.Token == "" {
        return api.Response{Success: false, Message: "Faltan credenciales"}
    }
    if !s.isTokenValid(req.Username, req.Token) {
        return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
    }

    // Obtener datos existentes (doble encriptados)
    encryptedData, err := s.db.Get("userdata", []byte(req.Username))
    if err != nil {
        log.Printf("[ERROR] Error al leer datos existentes: %v\n", err)
        return api.Response{Success: false, Message: "Error al leer datos existentes"}
    }

    count := 0
    var expedientes []string // Solo almacenamos los datos encriptados

    if len(encryptedData) > 0 {
        // Desencriptar la lista completa (segunda capa)
        decryptedList, err := descifrarString(string(encryptedData), key, iv)
        if err != nil {
            log.Printf("[ERROR] Error al descifrar lista existente: %v\n", err)
            return api.Response{Success: false, Message: "Error al descifrar datos existentes"}
        }

        // Extraer expedientes (cada uno sigue encriptado con la primera capa)
        if err := json.Unmarshal([]byte(decryptedList), &expedientes); err != nil {
            log.Printf("[WARN] Error al decodificar lista JSON, iniciando nueva: %v\n", err)
            expedientes = []string{}
        }
        count = len(expedientes)
    }

    // Crear nuevo expediente (ya viene encriptado del cliente)
    nuevoExpediente := map[string]interface{}{
        "id":             count + 1,
        "fecha_creacion": time.Now().Format(time.RFC3339),
        "datos":          req.Data, // Mantenemos los datos pre-encriptados
    }

    // Serializar el nuevo expediente (sin desencriptar los datos)
    nuevoExpedienteJSON, err := json.Marshal(nuevoExpediente)
    if err != nil {
        log.Printf("[ERROR] Error al serializar nuevo expediente: %v\n", err)
        return api.Response{Success: false, Message: "Error al crear expediente"}
    }

    // Agregar a la lista (como string para evitar problemas)
    expedientes = append(expedientes, string(nuevoExpedienteJSON))

    // Serializar lista completa
    listaJSON, err := json.Marshal(expedientes)
    if err != nil {
        log.Printf("[ERROR] Error al serializar lista: %v\n", err)
        return api.Response{Success: false, Message: "Error al preparar datos para almacenamiento"}
    }

    // Encriptar la lista completa (segunda capa)
    encryptedList, err := cifrarString(string(listaJSON), key, iv)
    if err != nil {
        log.Printf("[ERROR] Error al encriptar lista: %v\n", err)
        return api.Response{Success: false, Message: "Error al cifrar datos"}
    }

    // Guardar en la base de datos
    if err := s.db.Put("userdata", []byte(req.Username), []byte(encryptedList)); err != nil {
        log.Printf("[ERROR] Error al guardar en BD: %v\n", err)
        return api.Response{Success: false, Message: "Error al guardar expediente"}
    }

    log.Printf("[updateData] Expediente guardado correctamente. Total: %d\n", count+1)
    return api.Response{
        Success: true,
        Message: fmt.Sprintf("Expediente médico creado con ID %d", count+1),
        Data:    fmt.Sprintf("%d", count+1),
    }
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request) api.Response {
	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(req.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave:
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+username {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(username, token string) bool {
	storedSession, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}

	// Split the stored session data into token and timestamp
	parts := strings.Split(string(storedSession), ":")
	if len(parts) != 2 {
		return false
	}
	storedToken := parts[0]
	storedTimestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}

	// Check if the token matches
	if storedToken != token {
		return false
	}

	// Check if the token is expired (e.g., 1 hour expiration)
	expirationTime := int64(86400) // 1 day in seconds
	//La otra función está en minutos
	currentTime := time.Now().Unix()
	if currentTime-storedTimestamp > expirationTime {
		return false
	}

	return true
}
