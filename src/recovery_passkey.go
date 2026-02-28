package apm

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

type recoveryPasskeyUser struct {
	id          []byte
	name        string
	displayName string
	creds       []wa.Credential
}

func (u recoveryPasskeyUser) WebAuthnID() []byte                   { return u.id }
func (u recoveryPasskeyUser) WebAuthnName() string                 { return u.name }
func (u recoveryPasskeyUser) WebAuthnDisplayName() string          { return u.displayName }
func (u recoveryPasskeyUser) WebAuthnCredentials() []wa.Credential { return u.creds }

func newRecoveryWebAuthn(origin string) (*wa.WebAuthn, error) {
	return wa.New(&wa.Config{
		RPDisplayName: "APM Recovery",
		RPID:          "localhost",
		RPOrigins:     []string{origin},
	})
}

func RunRecoveryPasskeyRegistration() ([]byte, []byte, error) {
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, nil, err
	}
	user := recoveryPasskeyUser{id: userID, name: "apm-recovery", displayName: "APM Recovery"}

	cred, err := runPasskeyCeremony(user, true)
	if err != nil {
		return nil, nil, err
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, nil, err
	}
	return userID, credJSON, nil
}

func verifyRecoveryPasskey(userID []byte, credJSON []byte) error {
	var cred wa.Credential
	if err := json.Unmarshal(credJSON, &cred); err != nil {
		return fmt.Errorf("invalid stored passkey credential: %w", err)
	}
	user := recoveryPasskeyUser{id: userID, name: "apm-recovery", displayName: "APM Recovery", creds: []wa.Credential{cred}}
	_, err := runPasskeyCeremony(user, false)
	return err
}

func VerifyRecoveryPasskeyFromHeader(info RecoveryData) error {
	if !info.RecoveryPasskeyEnabled || len(info.RecoveryPasskeyUserID) == 0 || len(info.RecoveryPasskeyCred) == 0 {
		return fmt.Errorf("recovery passkey not configured")
	}
	return verifyRecoveryPasskey(info.RecoveryPasskeyUserID, info.RecoveryPasskeyCred)
}

func runPasskeyCeremony(user recoveryPasskeyUser, registration bool) (*wa.Credential, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	_, port, splitErr := net.SplitHostPort(listener.Addr().String())
	if splitErr != nil {
		return nil, splitErr
	}
	origin := "http://localhost:" + port
	webAuthn, err := newRecoveryWebAuthn(origin)
	if err != nil {
		return nil, err
	}

	var (
		sessionMu    sync.Mutex
		regSession   *wa.SessionData
		loginSession *wa.SessionData
	)

	resultCh := make(chan *wa.Credential, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, passkeyHTML(registration))
	})

	mux.HandleFunc("/options", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if registration {
			opts, session, err := webAuthn.BeginRegistration(user, wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			sessionMu.Lock()
			regSession = session
			sessionMu.Unlock()
			_ = json.NewEncoder(w).Encode(opts)
			return
		}
		opts, session, err := webAuthn.BeginLogin(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sessionMu.Lock()
		loginSession = session
		sessionMu.Unlock()
		_ = json.NewEncoder(w).Encode(opts)
	})

	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if registration {
			sessionMu.Lock()
			s := regSession
			sessionMu.Unlock()
			if s == nil {
				http.Error(w, "registration session not initialized", http.StatusBadRequest)
				return
			}
			cred, err := webAuthn.FinishRegistration(user, *s, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				errCh <- err
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			resultCh <- cred
			return
		}

		sessionMu.Lock()
		s := loginSession
		sessionMu.Unlock()
		if s == nil {
			http.Error(w, "login session not initialized", http.StatusBadRequest)
			return
		}
		cred, err := webAuthn.FinishLogin(user, *s, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			errCh <- err
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		resultCh <- cred
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	defer srv.Close()

	_ = openPasskeyBrowser(origin)

	select {
	case cred := <-resultCh:
		return cred, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(2 * time.Minute):
		return nil, fmt.Errorf("passkey ceremony timed out")
	}
}

func openPasskeyBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

func passkeyHTML(registration bool) string {
	mode := "get"
	if registration {
		mode = "create"
	}
	return fmt.Sprintf(`<!doctype html>
<html><body style="font-family: sans-serif; padding: 20px;">
<h2>APM Recovery Passkey %s</h2>
<p>Follow your browser/device prompt to continue.</p>
<pre id="status">Starting...</pre>
<script>
function b64urlToBuf(v){v=v.replace(/-/g,'+').replace(/_/g,'/');const pad=v.length%%4;if(pad)v += '='.repeat(4-pad);const s=atob(v);const b=new Uint8Array(s.length);for(let i=0;i<s.length;i++)b[i]=s.charCodeAt(i);return b;}
function bufToB64url(buf){const b=new Uint8Array(buf);let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function preformatCreate(o){if(o.challenge)o.challenge=b64urlToBuf(o.challenge);if(o.user&&o.user.id)o.user.id=b64urlToBuf(o.user.id);if(o.excludeCredentials) o.excludeCredentials=o.excludeCredentials.map(c=>({...c,id:b64urlToBuf(c.id)}));return o;}
function preformatGet(o){if(o.challenge)o.challenge=b64urlToBuf(o.challenge);if(o.allowCredentials) o.allowCredentials=o.allowCredentials.map(c=>({...c,id:b64urlToBuf(c.id)}));return o;}
function credToJSON(c){if(!c)return null;const r={id:c.id,rawId:bufToB64url(c.rawId),type:c.type,response:{}}; if(c.response.attestationObject) r.response.attestationObject=bufToB64url(c.response.attestationObject); if(c.response.clientDataJSON) r.response.clientDataJSON=bufToB64url(c.response.clientDataJSON); if(c.response.authenticatorData) r.response.authenticatorData=bufToB64url(c.response.authenticatorData); if(c.response.signature) r.response.signature=bufToB64url(c.response.signature); if(c.response.userHandle) r.response.userHandle=bufToB64url(c.response.userHandle); return r; }
(async()=>{const status=document.getElementById('status'); try{ const opts=await fetch('/options').then(r=>r.json()); const pk=opts.publicKey||opts; let cred; if('%s'==='create'){cred=await navigator.credentials.create({publicKey:preformatCreate(pk)});}else{cred=await navigator.credentials.get({publicKey:preformatGet(pk)});} const payload=credToJSON(cred); const resp=await fetch('/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}); if(!resp.ok){status.textContent='Failed: '+await resp.text(); return;} status.textContent='Success. You can return to terminal.';}catch(e){status.textContent='Error: '+e;}})();
</script>
</body></html>`, map[bool]string{true: "Registration", false: "Verification"}[registration], mode)
}
