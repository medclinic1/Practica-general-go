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

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/scrypt"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func generateIv(username string) []byte {
	//El iv debe ser diferente, generado en función del nombre del usuario cada vez que se inicia el servidor
	iv := obtenerSHA256(string(username))
	return iv
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

var key []byte

// Secret key for signing JWTs (use a secure, random key in production)
var jwtSecret []byte

// Run inicia la base de datos y arranca el servidor HTTP.
func Run(clavemaestra string) error {

	key = obtenerSHA256(clavemaestra)
	jwtSecret = key

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
	case api.ActionEliminarData:
		res = s.eliminarexpediente(req)
	case api.ActionActualizarData:
		res = s.actualizarData(req)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// generateToken crea un token aleatorio
func (s *server) generateToken(username string) (string, error) {
	// Define the claims for the token
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(), // Token expires in 24 hours
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
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

	iv := generateIv(req.Username)
	//Guardamos las claves pública y privada

	if err := s.db.Put("clavesPub", []byte(req.Username), []byte(req.keyLogin)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	criptdkey, err := cifrarString(string(req.keyData), key, iv)
	if err := s.db.Put("clavesPri", []byte(req.Username), []byte(criptdkey)); err != nil {
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

	// Compare
	if !bytes.Equal(hashedPassword, storedHash) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Generate JWT
	token, err := s.generateToken(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar token"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: token}
}

// fetchData verifica el token y retorna todos los expedientes médicos desencriptados
func (s *server) fetchData(req api.Request) api.Response {
	//log.Println("[fetchData] Iniciando función para usuario:", req.Username)
	iv := generateIv(req.Username)

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
		log.Println()
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
	iv := generateIv(req.Username)

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

	var expedientes []string // Solo almacenamos los datos encriptados
	lastID := 0

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

		if len(expedientes) > 0 {
			// Deserializar el último expediente para obtener su ID
			var lastExpediente map[string]interface{}
			if err := json.Unmarshal([]byte(expedientes[len(expedientes)-1]), &lastExpediente); err == nil {
				if id, ok := lastExpediente["id"].(float64); ok {
					lastID = int(id)
				}
			}
		}

	}

	// Crear nuevo expediente (ya viene encriptado del cliente)
	nuevoExpediente := map[string]interface{}{
		"id":             lastID + 1,
		"fecha_creacion": time.Now().Format("02/01/2006 15:04:05"),
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

	log.Printf("[updateData] Expediente guardado correctamente. Total: %d\n", lastID+1)
	return api.Response{
		Success: true,
		Message: fmt.Sprintf("Expediente médico creado con ID %d", lastID+1),
		Data:    fmt.Sprintf("%d", lastID+1),
	}
}

// Elimina de la base de datos un expediente según un ID de expediente
func (s *server) eliminarexpediente(req api.Request) api.Response {
	iv := generateIv(req.Username)
	log.Println("[eliminarexpediente] Iniciando eliminación de expediente")

	// Validar credenciales
	if req.Username == "" || req.Token == "" {
		log.Println("[ERROR] Faltan credenciales")
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		log.Println("[ERROR] Token inválido")
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtener ID del expediente
	idEliminar, err := strconv.Atoi(req.Data)
	if err != nil {
		log.Printf("[ERROR] ID no válido: %v\n", err)
		return api.Response{Success: false, Message: "ID de expediente no válido"}
	}

	// Obtener datos encriptados
	encryptedData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		log.Printf("[ERROR] Error al leer BD: %v\n", err)
		return api.Response{Success: false, Message: "Error al obtener expedientes"}
	}

	if len(encryptedData) == 0 {
		log.Println("[WARN] No hay expedientes para el usuario")
		return api.Response{Success: false, Message: "El usuario no tiene expedientes"}
	}

	// Desencriptar datos (código anterior igual hasta...)
	decryptedData, err := descifrarString(string(encryptedData), key, iv)
	if err != nil {
		log.Printf("[ERROR] Error al descifrar: %v\n", err)
		return api.Response{Success: false, Message: "Error al procesar expedientes"}
	}

	// Primero: Deserializar el array de strings JSON
	var expedientesJSON []string
	if err := json.Unmarshal([]byte(decryptedData), &expedientesJSON); err != nil {
		log.Printf("[ERROR] Error al parsear lista de expedientes: %v\n", err)
		return api.Response{Success: false, Message: "Error al leer expedientes"}
	}

	// Segundo: Procesar cada expediente individualmente
	var expedientes []map[string]interface{}
	for _, expJSON := range expedientesJSON {
		var expediente map[string]interface{}
		if err := json.Unmarshal([]byte(expJSON), &expediente); err != nil {
			log.Printf("[WARN] Error al parsear expediente: %v\n", err)
			continue
		}
		expedientes = append(expedientes, expediente)
	}

	// Filtrar expedientes (código anterior igual)
	var expedientesActualizados []map[string]interface{}
	eliminado := false

	for _, exp := range expedientes {
		id, ok := exp["id"].(float64)
		if !ok {
			log.Println("[WARN] Expediente sin ID válido")
			continue
		}

		if int(id) == idEliminar {
			log.Printf("[INFO] Expediente %d marcado para eliminación\n", idEliminar)
			eliminado = true
			continue
		}

		// Convertir el expediente de nuevo a string JSON para mantener el formato
		expJSON, err := json.Marshal(exp)
		if err != nil {
			log.Printf("[WARN] Error al serializar expediente: %v\n", err)
			continue
		}
		expedientesActualizados = append(expedientesActualizados, map[string]interface{}{
			"json": string(expJSON),
		})
	}

	if !eliminado {
		log.Printf("[WARN] Expediente %d no encontrado\n", idEliminar)
		return api.Response{Success: false, Message: "No se encontró el expediente"}
	}

	// Preparar lista actualizada manteniendo el formato original
	var expedientesActualizadosJSON []string
	for _, exp := range expedientesActualizados {
		if jsonStr, ok := exp["json"].(string); ok {
			expedientesActualizadosJSON = append(expedientesActualizadosJSON, jsonStr)
		}
	}

	// Serializar la lista actualizada
	expedientesJSONActualizados, err := json.Marshal(expedientesActualizadosJSON)
	if err != nil {
		log.Printf("[ERROR] Error al serializar: %v\n", err)
		return api.Response{Success: false, Message: "Error al actualizar expedientes"}
	}

	// Resto del código (encriptar y guardar) igual...
	encryptedUpdated, err := cifrarString(string(expedientesJSONActualizados), key, iv)
	if err != nil {
		log.Printf("[ERROR] Error al encriptar: %v\n", err)
		return api.Response{Success: false, Message: "Error al proteger expedientes"}
	}

	// Guardar cambios
	if err := s.db.Put("userdata", []byte(req.Username), []byte(encryptedUpdated)); err != nil {
		log.Printf("[ERROR] Error al guardar: %v\n", err)
		return api.Response{Success: false, Message: "Error al guardar cambios"}
	}

	log.Printf("[SUCCESS] Expediente %d eliminado correctamente\n", idEliminar)
	return api.Response{
		Success: true,
		Message: fmt.Sprintf("Expediente %d eliminado correctamente", idEliminar),
	}
}

// actualizarData maneja la actualización de expedientes médicos existentes
func (s *server) actualizarData(req api.Request) api.Response {
	iv := generateIv(req.Username)

	// Validar credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Parsear los datos de actualización (ID + nuevos datos)
	var updateRequest struct {
		ID   int    `json:"id"`
		Data string `json:"data"` // Datos ya encriptados por el cliente
	}
	if err := json.Unmarshal([]byte(req.Data), &updateRequest); err != nil {
		log.Printf("[ERROR] Error al parsear datos de actualización: %v\n", err)
		return api.Response{Success: false, Message: "Formato de datos inválido"}
	}

	// Obtener datos existentes
	encryptedData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		log.Printf("[ERROR] Error al leer datos existentes: %v\n", err)
		return api.Response{Success: false, Message: "Error al leer datos existentes"}
	}

	if len(encryptedData) == 0 {
		return api.Response{Success: false, Message: "No hay expedientes para actualizar"}
	}

	// Desencriptar la lista completa (segunda capa)
	decryptedList, err := descifrarString(string(encryptedData), key, iv)
	if err != nil {
		log.Printf("[ERROR] Error al descifrar lista existente: %v\n", err)
		return api.Response{Success: false, Message: "Error al descifrar datos existentes"}
	}

	// Extraer expedientes
	var expedientes []string
	if err := json.Unmarshal([]byte(decryptedList), &expedientes); err != nil {
		log.Printf("[ERROR] Error al decodificar lista JSON: %v\n", err)
		return api.Response{Success: false, Message: "Error al procesar expedientes"}
	}

	// Buscar y actualizar el expediente
	expedienteEncontrado := false
	var nuevosExpedientes []string

	for _, exp := range expedientes {
		var expediente map[string]interface{}
		if err := json.Unmarshal([]byte(exp), &expediente); err != nil {
			log.Printf("[WARN] Error al decodificar expediente, omitiendo: %v\n", err)
			nuevosExpedientes = append(nuevosExpedientes, exp)
			continue
		}

		// Verificar si es el expediente a actualizar
		if int(expediente["id"].(float64)) == updateRequest.ID {
			expedienteEncontrado = true
			// Actualizar solo los datos, mantener ID y fecha de creación
			expediente["datos"] = updateRequest.Data
			expedienteActualizado, _ := json.Marshal(expediente)
			nuevosExpedientes = append(nuevosExpedientes, string(expedienteActualizado))
			log.Printf("[actualizarData] Expediente %d actualizado\n", updateRequest.ID)
		} else {
			nuevosExpedientes = append(nuevosExpedientes, exp)
		}
	}

	if !expedienteEncontrado {
		return api.Response{Success: false, Message: fmt.Sprintf("Expediente con ID %d no encontrado", updateRequest.ID)}
	}

	// Serializar lista completa actualizada
	listaJSON, err := json.Marshal(nuevosExpedientes)
	if err != nil {
		log.Printf("[ERROR] Error al serializar lista actualizada: %v\n", err)
		return api.Response{Success: false, Message: "Error al preparar datos para almacenamiento"}
	}

	// Encriptar la lista completa (segunda capa)
	encryptedList, err := cifrarString(string(listaJSON), key, iv)
	if err != nil {
		log.Printf("[ERROR] Error al encriptar lista actualizada: %v\n", err)
		return api.Response{Success: false, Message: "Error al cifrar datos"}
	}

	// Guardar en la base de datos
	if err := s.db.Put("userdata", []byte(req.Username), []byte(encryptedList)); err != nil {
		log.Printf("[ERROR] Error al guardar en BD: %v\n", err)
		return api.Response{Success: false, Message: "Error al guardar expediente actualizado"}
	}

	return api.Response{
		Success: true,
		Message: fmt.Sprintf("Expediente médico con ID %d actualizado correctamente", updateRequest.ID),
		Data:    fmt.Sprintf("%d", updateRequest.ID),
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
	// Parse and validate the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return false
	}

	// Check the claims
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		// Ensure the username in the token matches the provided username
		if claims["username"] == username {
			return true
		}
	}

	return false
}
