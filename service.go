package main

import (
	"flag"
	"github.com/gorilla/mux"
	"github.com/mgutz/ansi"
	"gopkg.in/yaml.v1"
	"io"
	"io/ioutil"
	"labix.org/v2/mgo"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
)

var (
	local   = flag.String("local", "", "serve as webserver, example: 0.0.0.0:8000")
	tcp     = flag.String("tcp", "", "serve as FCGI via TCP, example: 0.0.0.0:8000")
	unix    = flag.String("unix", "", "serve as FCGI via UNIX socket, example /tmp/myprogram.sock")
	token   = flag.String("token", "", "oauth token")
	conf    = flag.String("conf", "", "secure configuration file (yml)")
	success = ansi.ColorCode("green")
	info    = ansi.ColorCode("white")
	fail    = ansi.ColorCode("red")
	warn    = ansi.ColorCode("yellow")
	reset   = ansi.ColorCode("reset")
	// TRACE is a logger for outputting tracing information
	TRACE *log.Logger
	// INFO is a logger for outputting regular information
	INFO *log.Logger
	// WARNING is a logger for ouputting information that may be dangerous
	WARNING *log.Logger
	// ERROR is a logger for putting information that is an error
	ERROR *log.Logger
	// secureConfig contains global constans read from a secure_config.yml file
	secureConfig map[string]string
)

// Session is a wrapper for a mongodb session
type Session struct {
	*mgo.Session
}

// NewSession creates a new mongodb sesssion
func NewSession() (*Session, error) {
	session, err := mgo.Dial("mongodb://localhost:27017")
	return &Session{session}, err
}

// User represents a red user right now, but there's no package
type User struct {
	Username          string
	Email             string
	EncryptedPassword string `bson:"encrypted_password" json:"encrypted_password"`
}

// SuccessMessage represents a json structure that tells us if we succeeded
type SuccessMessage struct {
	Success bool
	Message string `json:",omitempty"`
}

func setupLogger(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	// Set up log stuff
	TRACE = log.New(traceHandle, "TRACE: ",
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	INFO = log.New(infoHandle, info+"INFO: "+reset,
		log.Ldate|log.Ltime|log.Lmicroseconds)
	WARNING = log.New(warningHandle, warn+"WARNING: "+reset,
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	ERROR = log.New(errorHandle, fail+"ERROR: "+reset,
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)

}

func main() {
	flag.Parse()

	if *conf != "" {
		b, err := ioutil.ReadFile(*conf)
		if err != nil {
			ERROR.Fatalln(err)
		}

		err = yaml.Unmarshal(b, &secureConfig)

		if err != nil {
			ERROR.Fatalln(err)
		}
	} else {
		ERROR.Fatalln("Secure Config file not specified")
	}
	// Setup logging output
	setupLogger(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)

	// Connect to mongodb
	session, err := NewSession()
	defer session.Close()
	if err != nil {
		ERROR.Fatalln(err)
	}

	// Setup routing
	r := mux.NewRouter()
	r.Handle("/authenticate", AuthHandler(session)).Methods("POST")

	// The following is ripped from http://www.dav-muz.net/blog/2013/09/how-to-use-go-and-fastcgi/
	if *local != "" {
		INFO.Println("Local server started on", *local)
		err = http.ListenAndServe(*local, r)
	} else if *tcp != "" {
		listener, err := net.Listen("tcp", *tcp)
		if err != nil {
			ERROR.Fatalln(err)
		}
		defer listener.Close()

		INFO.Println("FCGI TCP Server started on", *tcp)
		err = fcgi.Serve(listener, r)
	} else if *unix != "" { // Run as FCGI via UNIX socket
		listener, err := net.Listen("unix", *unix)
		if err != nil {
			ERROR.Fatalln(err)
		}
		defer listener.Close()

		INFO.Println("FCGI Socket server started with file", *unix)
		err = fcgi.Serve(listener, r)
	} else { // Run as FCGI via standard I/O
		err = fcgi.Serve(nil, r)
	}

	// Check the err status on starting the web server
	if err != nil {
		ERROR.Fatalln(err)
	}
}
