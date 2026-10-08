package browser

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed testdata/home.html
var homeTemplate string
var page = template.Must(template.New("home").Parse(homeTemplate))

func testRender(w http.ResponseWriter, _ *http.Request, v View) {
	s := session{CSRF: v.CSRF}
	if v.Proof != nil {
		p := v.Proof.Identity()
		s.Proof = &p
	}
	_ = page.Execute(w, struct {
		Session session
		Central string
		Ready   bool
	}{s, v.CentralLogout, v.Proof != nil})
}
