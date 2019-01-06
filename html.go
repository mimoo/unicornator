package main

import(
	"html/template"
	"os"
)

const html_template = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{.Title}}</title>
</head>
<body>
    {{range .Items}}<div>{{ . }}</div>{{else}}<div><strong>no rows</strong></div>{{end}}
</body>
</html>`

func print_html_output(){

	tt := template.Must(template.New("webpage").Parse(html_template))

	data := struct {
		Title string
		Items []string
	}{
		Title: "Unicornator output",
		Items: []string{
			"My photos",
			"My blog",
		},
	}

	tt.Execute(os.Stdout, data)

}
