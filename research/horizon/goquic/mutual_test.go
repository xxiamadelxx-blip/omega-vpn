package mutualtest

// Ω Horizon laboratory only: genuine two-way QUIC TLS 1.3 certificate
// authentication via Go crypto/tls and quic-go public APIs.
// Test CA, leaf certs and P-256/X25519 session keys are library-generated.
// No public exit, user VPN packets or live firewall bypass testing.

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "errors"
    "fmt"
    "math/big"
    "net"
    "sync/atomic"
    "testing"
    "time"

    quic "github.com/quic-go/quic-go"
)

const alpn = "omega-horizon-go-mtls-lab"
const marker = "SYNTHETIC-OMEGA-PROBE-ONLY"

type labIdentity struct {
    tlsCert tls.Certificate
    parsed *x509.Certificate
}

func newLabCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
    t.Helper()
    public, private, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    tmpl := &x509.Certificate{
        SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OmegaTestCA"},
        NotBefore: time.Now().Add(-time.Minute),
        NotAfter: time.Now().Add(time.Hour),
        IsCA: true, BasicConstraintsValid: true,
        KeyUsage: x509.KeyUsageCertSign,
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, public, private)
    if err != nil { t.Fatal(err) }
    ca, err := x509.ParseCertificate(der)
    if err != nil { t.Fatal(err) }
    pool := x509.NewCertPool()
    pool.AddCert(ca)
    return ca, private, pool
}

func makeLeaf(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey,
    name string, usage x509.ExtKeyUsage) labIdentity {
    t.Helper()
    public, private, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
    if err != nil { t.Fatal(err) }
    tmpl := &x509.Certificate{
        SerialNumber: serial,
        Subject: pkix.Name{CommonName: name},
        DNSNames: []string{name},
        NotBefore: time.Now().Add(-time.Minute),
        NotAfter: time.Now().Add(45 * time.Minute),
        KeyUsage: x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{usage},
        BasicConstraintsValid: true,
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, public, caKey)
    if err != nil { t.Fatal(err) }
    parsed, err := x509.ParseCertificate(der)
    if err != nil { t.Fatal(err) }
    return labIdentity{
        tlsCert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: parsed},
        parsed: parsed,
    }
}

func pin(identity labIdentity) [32]byte {
    return sha256.Sum256(identity.parsed.RawSubjectPublicKeyInfo)
}

func pinnedConnection(expected [32]byte) func(tls.ConnectionState) error {
    return func(cs tls.ConnectionState) error {
        if len(cs.PeerCertificates) == 0 {
            return errors.New("peer certificate missing")
        }
        present := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
        if present != expected {
            return errors.New("peer SPKI identity does not match pinned key")
        }
        if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != alpn {
            return errors.New("TLS 1.3 / QUIC ALPN requirement unmet")
        }
        return nil
    }
}

func serverConfig(cert labIdentity, ca *x509.CertPool, pinnedClient [32]byte) *tls.Config {
    return &tls.Config{
        Certificates: []tls.Certificate{cert.tlsCert},
        NextProtos: []string{alpn},
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: ca,
        MinVersion: tls.VersionTLS13,
        VerifyConnection: pinnedConnection(pinnedClient),
    }
}

func clientConfig(cert labIdentity, ca *x509.CertPool, pinnedServer [32]byte) *tls.Config {
    return &tls.Config{
        Certificates: []tls.Certificate{cert.tlsCert},
        RootCAs: ca,
        ServerName: "omega-peer",
        NextProtos: []string{alpn},
        MinVersion: tls.VersionTLS13,
        VerifyConnection: pinnedConnection(pinnedServer),
    }
}

func launch(t *testing.T, conf *tls.Config) (string, *atomic.Int64) {
    t.Helper()
    l, err := quic.ListenAddr("127.0.0.1:0", conf, &quic.Config{EnableDatagrams:true})
    if err != nil {t.Fatal(err)}
    ctx, cancel := context.WithCancel(context.Background())
    t.Cleanup(func() { cancel();_ = l.Close() })
    accepted := &atomic.Int64{}
    go func() {
        for {
            conn, err := l.Accept(ctx)
            if err != nil {return}
            accepted.Add(1)
            go func(c *quic.Conn) {
                defer c.CloseWithError(0,"lab done")
                requestContext, requestCancel := context.WithTimeout(ctx, 3*time.Second)
                defer requestCancel()
                payload, err := c.ReceiveDatagram(requestContext)
                if err != nil {return}
                if !bytes.HasPrefix(payload, []byte(marker)) {return}
                if err = c.SendDatagram(append([]byte("ACK:"),payload...)); err != nil {return}
                time.Sleep(40*time.Millisecond)
            }(conn)
        }
    }()
    return l.Addr().String(), accepted
}

func exchange(addr string, cfg *tls.Config, wait time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), wait)
    defer cancel()
    conn, err := quic.DialAddr(ctx,addr,cfg,&quic.Config{EnableDatagrams:true})
    if err != nil {return err}
    defer conn.CloseWithError(0,"client done")
    expected := []byte("ACK:"+marker+":G2")
    if err = conn.SendDatagram([]byte(marker+":G2")); err != nil {return err}
    got, err := conn.ReceiveDatagram(ctx)
    if err != nil {return err}
    if !bytes.Equal(got,expected) {return fmt.Errorf("unauthenticated or wrong probe response")}
    if conn.ConnectionState().TLS.Version != tls.VersionTLS13 {
        return errors.New("QUIC TLS 1.3 not negotiated")
    }
    return nil
}

func TestMutualTLSQUICDatagram(t *testing.T) {
    ca, caKey, pool := newLabCA(t)
    server := makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client := makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    addr, counter := launch(t,serverConfig(server,pool,pin(client)))
    if err := exchange(addr,clientConfig(client,pool,pin(server)),3*time.Second); err != nil {t.Fatal(err)}
    if counter.Load() != 1 {t.Fatalf("expected exactly one authenticated client, got %d",counter.Load())}
}

func TestClientWithDifferentPinnedKeyRejected(t *testing.T) {
    ca, caKey, pool := newLabCA(t)
    server := makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client := makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    impostor := makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    addr, counter := launch(t,serverConfig(server,pool,pin(client)))
    err := exchange(addr,clientConfig(impostor,pool,pin(server)),1700*time.Millisecond)
    if err == nil {t.Fatal("impostor client bypassed server-side peer pin")}
    if counter.Load()!=0 {t.Fatalf("unauthorized client reached application, accepts=%d",counter.Load())}
}

func TestWrongServerPinnedKeyRejected(t *testing.T) {
    ca, caKey, pool := newLabCA(t)
    server := makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    replacement := makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client := makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    addr,_ := launch(t,serverConfig(replacement,pool,pin(client)))
    err := exchange(addr,clientConfig(client,pool,pin(server)),1700*time.Millisecond)
    if err == nil {t.Fatal("impostor server bypassed client peer pin")}
}

func TestNoClientCertRejected(t *testing.T) {
    ca, caKey, pool := newLabCA(t)
    server := makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client := makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    addr, counter := launch(t,serverConfig(server,pool,pin(client)))
    cfg:=clientConfig(client,pool,pin(server))
    cfg.Certificates=nil
    if err := exchange(addr,cfg,1700*time.Millisecond);err==nil {t.Fatal("client missing TLS certificate connected")}
    if counter.Load()!=0 {t.Fatalf("unauthenticated connection accepted: %d",counter.Load())}
}

func TestCertificateRotationRequiresExplicitNewPin(t *testing.T) {
    ca, caKey, pool := newLabCA(t)
    oldServer:=makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    rotated:=makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client:=makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    addr,_:=launch(t,serverConfig(rotated,pool,pin(client)))
    if err:=exchange(addr,clientConfig(client,pool,pin(oldServer)),1700*time.Millisecond);err==nil {t.Fatal("unapproved server rotation accepted")}
    if err:=exchange(addr,clientConfig(client,pool,pin(rotated)),3*time.Second);err!=nil {t.Fatalf("explicitly pinned rotation rejected: %v",err)}
}

func TestReconnectUsesFreshTLSHandshake(t *testing.T) {
    ca, caKey, pool := newLabCA(t)
    server:=makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client:=makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    addr,counter:=launch(t,serverConfig(server,pool,pin(client)))
    config:=clientConfig(client,pool,pin(server))
    for i:=0;i<3;i++ {
        if err:=exchange(addr,config,3*time.Second);err!=nil {t.Fatalf("reconnect %d failed: %v",i,err)}
    }
    if counter.Load()!=3 {t.Fatalf("wanted 3 authenticated QUIC sessions, got %d",counter.Load())}
}

func TestNoListenerNeverUsesUnprotectedFallback(t *testing.T) {
    ca, caKey, pool:=newLabCA(t)
    server:=makeLeaf(t,ca,caKey,"omega-peer",x509.ExtKeyUsageServerAuth)
    client:=makeLeaf(t,ca,caKey,"omega-client",x509.ExtKeyUsageClientAuth)
    local,err:=net.ListenPacket("udp","127.0.0.1:0")
    if err!=nil {t.Fatal(err)}
    addr:=local.LocalAddr().String()
    _=local.Close()
    if err:=exchange(addr,clientConfig(client,pool,pin(server)),1250*time.Millisecond);err==nil {
        t.Fatal("missing QUIC peer unexpectedly accepted application datagram")
    }
}
