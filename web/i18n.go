package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed i18n/*.json
var catalogs embed.FS

// Translator holds the texts of the panel in one language. A key missing
// from the language falls back to English, and then to the key itself.
type Translator struct {
	lang     string
	texts    map[string]string
	fallback map[string]string
}

// Languages are the catalogs shipped with the panel.
var Languages = []string{"en", "pt-BR"}

// NewTranslator loads a language ("en", "pt-BR"); "" is English.
func NewTranslator(lang string) (*Translator, error) {
	if lang == "" {
		lang = "en"
	}
	load := func(l string) (map[string]string, error) {
		raw, err := catalogs.ReadFile("i18n/" + l + ".json")
		if err != nil {
			return nil, fmt.Errorf("no catalog for language %q (have %s)", l, strings.Join(Languages, ", "))
		}
		m := map[string]string{}
		return m, json.Unmarshal(raw, &m)
	}
	en, err := load("en")
	if err != nil {
		return nil, err
	}
	t := &Translator{lang: lang, texts: en, fallback: en}
	if lang != "en" {
		if t.texts, err = load(lang); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// Lang is the language code, for <html lang>.
func (t *Translator) Lang() string { return t.lang }

// T returns the text of a key, formatted with args as in fmt.Sprintf.
func (t *Translator) T(key string, args ...any) string {
	s, ok := t.texts[key]
	if !ok {
		if s, ok = t.fallback[key]; !ok {
			s = key
		}
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}
