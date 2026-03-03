package autofill

import "strings"

type SequenceActionType string

const (
	ActionText  SequenceActionType = "text"
	ActionTab   SequenceActionType = "tab"
	ActionEnter SequenceActionType = "enter"
)

type SequenceAction struct {
	Type SequenceActionType `json:"type"`
	Text string             `json:"text,omitempty"`
}

func renderSequence(template, username, password, totp string) []SequenceAction {
	if strings.TrimSpace(template) == "" {
		template = DefaultSequenceTemplate
	}

	var out []SequenceAction
	var textBuilder strings.Builder

	flushText := func() {
		if textBuilder.Len() == 0 {
			return
		}
		out = append(out, SequenceAction{Type: ActionText, Text: textBuilder.String()})
		textBuilder.Reset()
	}

	for i := 0; i < len(template); {
		if template[i] != '{' {
			textBuilder.WriteByte(template[i])
			i++
			continue
		}

		end := strings.IndexByte(template[i:], '}')
		if end <= 0 {
			textBuilder.WriteByte(template[i])
			i++
			continue
		}

		end = i + end
		token := strings.ToUpper(strings.TrimSpace(template[i+1 : end]))
		i = end + 1

		switch token {
		case "USERNAME":
			textBuilder.WriteString(username)
		case "PASSWORD":
			textBuilder.WriteString(password)
		case "TOTP":
			textBuilder.WriteString(totp)
		case "TAB":
			flushText()
			out = append(out, SequenceAction{Type: ActionTab})
		case "ENTER":
			flushText()
			out = append(out, SequenceAction{Type: ActionEnter})
		default:
			textBuilder.WriteString("{" + token + "}")
		}
	}
	flushText()
	return out
}
