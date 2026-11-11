package hcore

/*
#include "stdint.h"
*/

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/hiddify/hiddify-core/v2/hello"
	hutils "github.com/hiddify/hiddify-core/v2/hutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/hiddify/hiddify-core/v2/db"
	_ "google.golang.org/grpc/encoding/gzip"
)

type CoreService struct {
	UnimplementedCoreServer
}

func StartGrpcServer(listenAddressG string, service string) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		log.Printf("failed to listen: %v", err)
		return nil, err
	}
	s := grpc.NewServer()
	if service == "core" {
		// Setup("./tmp/", "./tmp", "./tmp", 11111, false)
		RegisterCoreServer(s, &CoreService{})
		// pb.RegisterExtensionHostServiceServer(s, &extension.ExtensionHostService{})
	} else if service == "hello" {
		// RegisterHelloServer(s, &hello.HelloService{})
	} else if service == "tunnel" {
		// RegisterTunnelServiceServer(s, &TunnelService{})
	}
	log.Printf("Server listening on %s", listenAddressG)
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("failed to serve: %v", err)
		}
		log.Printf("Server stopped")
		// cancel()
	}()
	return s, nil
}

func StartCoreGrpcServer(listenAddressG string) (*grpc.Server, error) {
	return StartGrpcServer(listenAddressG, "core")
}

func StartHelloGrpcServer(listenAddressG string) (*grpc.Server, error) {
	return StartGrpcServer(listenAddressG, "hello")
}

var (
	certpair   *hutils.CertificatePair
	grpcServer map[SetupMode]*grpc.Server = make(map[SetupMode]*grpc.Server)
	// Client identities the app has registered, by SHA-256 of the raw
	// certificate DER, resp. of the PKIX public-key DER. The server trusts a
	// client exactly when it presents one of these; chain verification against
	// a CA pool cannot work because the app's client certificate is a
	// self-signed end-entity certificate, not a CA.
	registeredMu            sync.Mutex
	registeredClientCerts   = map[string]struct{}{}
	registeredClientKeys    = map[string]struct{}{}
)

// StartGrpcServerByMode starts a gRPC server on the specified address with mTLS.
func StartGrpcServerByMode(listenAddressG string, mode SetupMode) (*grpc.Server, error) {
	if !strings.Contains(listenAddressG, ":") {
		return nil, fmt.Errorf("invalid listen address (no port): %s", listenAddressG)
	}
	// Convert the port from string to uint16
	portStr := strings.Split(listenAddressG, ":")[1]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to convert port %s to uint16: %v", portStr, err)
	}
	if hutils.IsPortInUse(uint16(port)) {
		return nil, fmt.Errorf("port %s is already in use", portStr)
	}
	// Fetch the server private key and public key from the database
	if _, exists := grpcServer[mode]; exists {
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already started")
		return grpcServer[mode], nil
	}

	if mode == SetupMode_GRPC_BACKGROUND_INSECURE || mode == SetupMode_GRPC_NORMAL_INSECURE {
		grpcServer[mode] = grpc.NewServer()
	} else {
		table := db.GetTable[hcommon.AppSettings]()
		Log(LogLevel_DEBUG, LogType_CORE, table)
		grpcServerPrivateKey, err := table.Get("grpc_server_private_key")
		grpcServerPublicKey, err2 := table.Get("grpc_server_public_key")
		if err != nil || err2 != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to get grpc_server_private_key and grpc_server_public_key from database: %v %v\n", err, err2))
			certpair, err = hutils.GenerateCertificatePair()
			if err != nil {
				Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to generate certificate pair: %v", err))

				return nil, err
			}
			table.UpdateInsert(
				&hcommon.AppSettings{Id: "grpc_server_public_key", Value: certpair.Certificate},
				&hcommon.AppSettings{Id: "grpc_server_private_key", Value: certpair.PrivateKey},
			)
		} else {
			certpair = &hutils.CertificatePair{
				Certificate: grpcServerPublicKey.Value.([]byte),
				PrivateKey:  grpcServerPrivateKey.Value.([]byte),
			}
		}
		// Load server certificate and private key
		serverCert, err := tls.X509KeyPair(certpair.Certificate, certpair.PrivateKey)
		if err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to load server certificate and key: %v\n", err))

			return nil, err
		}

		// Create TLS credentials for the gRPC server
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			// Require a client certificate, but verify it against the
			// registered identities (below) instead of a CA pool: the app's
			// client certificate is self-signed and not a CA, so chain
			// verification against ClientCAs can never accept it.
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: verifyRegisteredClientCert,
		}

		// Create a new gRPC server with TLS credentials
		creds := credentials.NewTLS(tlsConfig)
		grpcServer[mode] = grpc.NewServer(grpc.Creds(creds))
	}
	// Register your gRPC service here
	RegisterCoreServer(grpcServer[mode], &CoreService{})
	hello.RegisterHelloServer(grpcServer[mode], &hello.HelloService{})
	// Listen on the provided address
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to listen on %s: %v\n", listenAddressG, err))
		return nil, err
	}
	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("grpcServer started on %s\n", listenAddressG))
	log.Printf("Server listening on %s", listenAddressG)

	// Run the server in a goroutine
	go func() {
		defer config.DeferPanicToError("grpcsetup", func(err error) {
			Log(LogLevel_FATAL, LogType_CORE, err.Error())
			<-time.After(5 * time.Second)
		})
		if err := grpcServer[mode].Serve(lis); err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to serve: %v\n", err))
		}
		Log(LogLevel_DEBUG, LogType_CORE, "Server stopped")
	}()

	return grpcServer[mode], nil
}

// GetGrpcServerPublicKey returns the gRPC server's public key.
func GetGrpcServerPublicKey() []byte {
	return certpair.Certificate
}

// AddGrpcClientPublicKey registers a client identity the gRPC server trusts:
// either a "CERTIFICATE" PEM (the app's self-signed client certificate) or a
// bare "PUBLIC KEY" PEM (legacy). Registration is by SHA-256 of the raw
// certificate DER, resp. of the PKIX public-key DER.
func AddGrpcClientPublicKey(clientPublicKey []byte) error {
	block, _ := pem.Decode(clientPublicKey)
	if block == nil {
		return fmt.Errorf("failed to decode client public key")
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse client certificate: %v", err)
		}
		registeredMu.Lock()
		registeredClientCerts[fmt.Sprintf("%x", sha256.Sum256(cert.Raw))] = struct{}{}
		registeredClientKeys[pubKeyHash(cert.PublicKey)] = struct{}{}
		registeredMu.Unlock()
		return nil
	case "PUBLIC KEY":
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse client public key: %v", err)
		}
		registeredMu.Lock()
		registeredClientKeys[pubKeyHash(pubKey)] = struct{}{}
		registeredMu.Unlock()
		return nil
	default:
		return fmt.Errorf("failed to decode client public key")
	}
}

func pubKeyHash(pubKey any) string {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(der))
}

// verifyRegisteredClientCert accepts the handshake only when the client
// presents a registered certificate (exact DER match) or a certificate whose
// public key was registered. With no registration at all it rejects: the
// server never serves an unregistered client.
func verifyRegisteredClientCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no client certificate presented")
	}
	registeredMu.Lock()
	defer registeredMu.Unlock()
	if len(registeredClientCerts) == 0 && len(registeredClientKeys) == 0 {
		return errors.New("no client certificate registered")
	}
	sum := sha256.Sum256(rawCerts[0])
	if _, ok := registeredClientCerts[fmt.Sprintf("%x", sum)]; ok {
		return nil
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %v", err)
	}
	if h := pubKeyHash(cert.PublicKey); h != "" {
		if _, ok := registeredClientKeys[h]; ok {
			return nil
		}
	}
	return errors.New("unknown client certificate")
}

func CloseGrpcServer(mode SetupMode) {
	if server, ok := grpcServer[mode]; ok && server != nil {
		server.Stop()
		delete(grpcServer, mode)
	}
}
