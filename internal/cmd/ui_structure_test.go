package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Guards the layout structure of the embedded UI.
//
// A missing </div> in index.html nested #view-connected inside #view-login.
// Both views carry inline display:flex/none, so switching to the connected view
// hid the whole subtree: the app showed a blank black window after a successful
// login while nothing threw and no other test noticed. These tests assert the
// structural invariants directly, which a Go unit test can check cheaply.

var (
	divOpenRe  = regexp.MustCompile(`<div\b`)
	divCloseRe = regexp.MustCompile(`</div>`)
	// voidContentTags are elements that never take a closing tag; they matter
	// only so the scanner does not misread their attributes.
	tagRe = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9-]*)([^>]*)>`)
)

func readUI(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(uiEmbedFS, "ui/"+name)
	if err != nil {
		t.Fatalf("read embedded ui/%s: %v", name, err)
	}
	return string(data)
}

// TestIndexHTMLDivsAreBalanced catches the class of defect that produced the
// post-login black screen: an unbalanced <div> lets the browser re-parent later
// sections into an element that is display:none.
func TestIndexHTMLDivsAreBalanced(t *testing.T) {
	html := readUI(t, "index.html")
	if got, want := len(divOpenRe.FindAllString(html, -1)), len(divCloseRe.FindAllString(html, -1)); got != want {
		t.Fatalf("unbalanced <div> tags: %d opening, %d closing", got, want)
	}

	// Walk the tags and fail at the first depth-0 close or a non-zero final
	// depth, which is what re-parenting looks like.
	depth := 0
	for _, m := range tagRe.FindAllStringSubmatchIndex(html, -1) {
		name := html[m[4]:m[5]]
		if name != "div" {
			continue
		}
		if html[m[2]:m[3]] == "/" {
			depth--
			if depth < 0 {
				t.Fatal("index.html closes a <div> that was never opened")
			}
			continue
		}
		depth++
	}
	if depth != 0 {
		t.Fatalf("index.html leaves %d <div> element(s) unclosed", depth)
	}
}

// TestUIRootViewsAreSiblings is the precise invariant the black screen broke:
// #view-login and #view-connected must be siblings at the top level, never
// nested, because switching views toggles display on exactly these two nodes.
func TestUIRootViewsAreSiblings(t *testing.T) {
	html := readUI(t, "index.html")

	loginIdx := strings.Index(html, `id="view-login"`)
	connectedIdx := strings.Index(html, `id="view-connected"`)
	if loginIdx < 0 || connectedIdx < 0 {
		t.Fatalf("root views missing (login=%d connected=%d)", loginIdx, connectedIdx)
	}
	if connectedIdx < loginIdx {
		t.Fatal("#view-connected appears before #view-login; expected the login view first")
	}

	// Count div depth at each view's opening tag. Both must sit at depth 1
	// (direct children of <body>), which also proves they are siblings.
	depths := map[string]int{}
	depth := 0
	for _, m := range tagRe.FindAllStringSubmatchIndex(html, -1) {
		name := html[m[4]:m[5]]
		if name != "div" {
			continue
		}
		closing := html[m[2]:m[3]] == "/"
		if closing {
			depth--
			continue
		}
		depth++
		tagStart := m[0]
		rest := html[tagStart:]
		switch {
		case strings.HasPrefix(rest, `<div id="view-login"`):
			depths["view-login"] = depth
		case strings.HasPrefix(rest, `<div id="view-connected"`):
			depths["view-connected"] = depth
		}
	}

	if depths["view-login"] != 1 {
		t.Fatalf("#view-login depth = %d, want 1 (direct child of <body>)", depths["view-login"])
	}
	if depths["view-connected"] != 1 {
		t.Fatalf("#view-connected depth = %d, want 1 — nested views hide the whole app "+
			"when the login view is display:none", depths["view-connected"])
	}
}

// TestUIViewIDsAreUnique keeps getElementById lookups unambiguous.
func TestUIViewIDsAreUnique(t *testing.T) {
	html := readUI(t, "index.html")
	idRe := regexp.MustCompile(`id="([^"]+)"`)
	seen := map[string]int{}
	for _, m := range idRe.FindAllStringSubmatch(html, -1) {
		seen[m[1]]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("duplicate id %q appears %d times; getElementById would return the first", id, n)
		}
	}
}

// TestAppJSReferencesExistingIDs catches renamed/removed elements: a lookup
// that returns null throws at the first property access, which surfaces to the
// user as a dead button rather than an error dialog.
//
// Only #id selectors are checked: class selectors often target nodes the script
// creates at runtime (certificate cards, table rows), so they are not required
// to exist in the static markup.
func TestAppJSReferencesExistingIDs(t *testing.T) {
	html := readUI(t, "index.html")
	js := readUI(t, "app.js")

	htmlIDs := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		htmlIDs[m[1]] = true
	}

	getByID := regexp.MustCompile(`getElementById\('([^']+)'\)`)
	for _, m := range getByID.FindAllStringSubmatch(js, -1) {
		if !htmlIDs[m[1]] {
			t.Errorf("app.js calls getElementById('%s') but index.html has no such id", m[1])
		}
	}

	idSelector := regexp.MustCompile(`querySelector(?:All)?\('#([A-Za-z0-9_-]+)'\)`)
	for _, m := range idSelector.FindAllStringSubmatch(js, -1) {
		if !htmlIDs[m[1]] {
			t.Errorf("app.js queries '#%s' but index.html has no such id", m[1])
		}
	}
}
