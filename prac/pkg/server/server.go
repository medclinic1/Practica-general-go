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
	"sync/atomic"

	"prac/pkg/api"
	"prac/pkg/store"

	"golang.org/x/crypto/scrypt"
)

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
func Run() error {

	key := obtenerSHA256("Clave")
	err := os.WriteFile("key.txt", []byte(key), 0755)
	if err != nil {
		fmt.Printf("unable to write file: %v", err)
	}

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
func (s *server) generateToken() string {
	id := atomic.AddInt64(&s.tokenCounter, 1) // atomic es necesario al haber paralelismo en las peticiones HTTP.
	return fmt.Sprintf("token_%d", id)
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
var hsh []byte

func (s *server) registerUser(req api.Request) api.Response {

	//Salt
	salt := make([]byte, 16)
	rand.Read(salt)
	pass := decode64(req.Password)
	hsh, _ = scrypt.Key(pass, salt, 16384, 8, 1, 32)

	// Validación básica
	if req.Username == "" || len(pass) == 0 {
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

	// Almacenamos la contraseña en el namespace 'auth' (clave=nombre, valor=contraseña)
	if err := s.db.Put("auth", []byte(req.Username), []byte(req.Password)); err != nil {
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
	//Cambio
	pass := decode64(req.Password)
	if req.Username == "" || len(pass) == 0 {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Recogemos la contraseña guardada en 'auth'
	//Añado decode64
	storedPass, err := s.db.Get("auth", []byte(req.Username))
	storedPass = decode64(string(storedPass))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Comparamos
	if string(storedPass) != string(pass) {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	//Comparamos
	salt := make([]byte, 16)
	hash, _ := scrypt.Key(pass, salt, 16384, 8, 1, 32) // scrypt(contraseña)
	if !bytes.Equal(hsh, hash) {                       // comparamos
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}
	// Generamos un nuevo token, lo guardamos en 'sessions'
	token := s.generateToken()
	if err := s.db.Put("sessions", []byte(req.Username), []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	return api.Response{Success: true, Message: "Login exitoso", Token: token}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request) api.Response {
	// Leer key e iv de los archivos creados
	key, err := os.ReadFile("key.txt")
	check(err)
	iv, err2 := os.ReadFile("iv.txt")
	check(err2)

	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", []byte(req.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	// Desencriptar aquí rawData
	textoEnClaroDescifrado, err := descifrarString(string(rawData), key, iv)
	if err != nil {
		return api.Response{Success: false, Message: "Error al descifrar datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + req.Username,
		Data:    textoEnClaroDescifrado,
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(req api.Request) api.Response {
	// Leer key e iv de los archivos creados
	key, err := os.ReadFile("key.txt")
	check(err)
	iv, err2 := os.ReadFile("iv.txt")
	check(err2)

	// Chequeo de credenciales
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Encriptar aquí req.Data.
	encryptedData, err := cifrarString(req.Data, key, iv)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar datos del usuario"}
	}
	fmt.Println("Encriptados: ", encryptedData, "Desencriptados: ", req.Data)

	// Escribimos el nuevo dato en 'userdata'
	if err := s.db.Put("userdata", []byte(req.Username), []byte(encryptedData)); err != nil {
		return api.Response{Success: false, Message: "Error al actualizar datos del usuario"}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
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
	storedToken, err := s.db.Get("sessions", []byte(username))
	if err != nil {
		return false
	}
	return string(storedToken) == token
}
