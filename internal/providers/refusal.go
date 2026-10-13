package providers

import "strings"

// LooksLikeRefusal catches the refusals models write as ordinary text rather
// than through the API's refusal field. Caching one would turn a transient
// over-refusal into a permanent one for every later caller with that question.
func LooksLikeRefusal(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	if len(t) > 400 {
		t = t[:400]
	}
	t = strings.ReplaceAll(t, "’", "'")
	for _, p := range []string{
		"i'm sorry, but i can't", "i can't help with", "i cannot help with", "i can't comply",
		"i cannot comply", "i'm unable to", "i am unable to", "i can't assist", "i cannot assist",
		"i won't be able to", "sorry, i can't", "i must decline",
	} {
		if strings.Contains(t, p) {
			return true
		}
	}
	return false
}
