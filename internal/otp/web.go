package otp

import (
	"html/template"
	"net/http"
)

var pageTmpl = template.Must(template.New("otp").Parse(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xtunnel OTP</title>
<style>
body { font-family: system-ui, sans-serif; background: #f4f5f7; color: #1f2328; margin: 0; padding: 16px; }
main { max-width: 420px; margin: 40px auto; background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
h1 { font-size: 20px; margin: 0 0 8px; }
p { color: #555; }
input { width: 100%; box-sizing: border-box; font-size: 22px; padding: 10px; letter-spacing: 4px; border: 1px solid #ccc; border-radius: 6px; }
button { margin-top: 12px; width: 100%; font-size: 16px; padding: 10px; border: 0; border-radius: 6px; background: #0b6bcb; color: #fff; cursor: pointer; }
.ok { color: #1a7f37; } .err { color: #cf222e; }
</style>
</head>
<body>
<main>
{{if .Done}}
  <h1 class="ok">Code sent</h1>
  <p>VPN <b>{{.VPN}}</b> is logging in with your code.</p>
{{else if .Error}}
  <h1 class="err">{{.Error}}</h1>
{{else}}
  <h1>VPN {{.VPN}}</h1>
  <p>{{.Prompt}}</p>
  <form method="post">
    <input name="code" autocomplete="one-time-code" inputmode="numeric" autofocus required>
    <button type="submit">Submit</button>
  </form>
  <p>Expires at {{.Expires}}</p>
{{end}}
</main>
</body>
</html>
`))

type pageData struct {
	VPN     string
	Prompt  string
	Expires string
	Error   string
	Done    bool
}

func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /otp/{id}", b.handleForm)
	mux.HandleFunc("POST /otp/{id}", b.handleSubmit)
	return mux
}

func (b *Broker) handleForm(w http.ResponseWriter, r *http.Request) {
	req, ok := b.lookup(r.PathValue("id"))
	if !ok {
		renderPage(w, http.StatusNotFound, pageData{Error: "Request expired or already answered"})
		return
	}
	renderPage(w, http.StatusOK, pageData{
		VPN:     req.vpn,
		Prompt:  req.prompt,
		Expires: req.expires.Format("15:04:05"),
	})
}

func (b *Broker) handleSubmit(w http.ResponseWriter, r *http.Request) {
	req, err := b.resolve(r.PathValue("id"), r.FormValue("code"))
	if err != nil {
		renderPage(w, http.StatusBadRequest, pageData{Error: err.Error()})
		return
	}
	renderPage(w, http.StatusOK, pageData{VPN: req.vpn, Done: true})
}

func renderPage(w http.ResponseWriter, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = pageTmpl.Execute(w, data)
}
