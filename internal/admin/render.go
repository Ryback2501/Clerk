package admin

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/web"
)

// contentSecurityPolicy allows only this origin's own stylesheet, font and
// script — no inline code of any kind — and fetches back to this origin alone.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; connect-src 'self'; " +
	"style-src 'self'; font-src 'self'; img-src 'self' data:; form-action 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'"

// newPageData builds the common view model and issues the CSRF token the
// rendered forms will carry.
func (h *Handler) newPageData(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, title string) pageData {
	token := h.csrf.Issue(w, r)
	return pageData{
		Title:     title,
		Admin:     admin,
		CSRFToken: token,
		CSRFField: web.CSRFFieldName,
		SignedIn:  admin != nil && h.oauth != nil,
		Register:  registerForm{CSRFToken: token},
	}
}

// render writes a page. A page with an administrator is drawn inside the
// application bar; one without — sign-in, or an error before anyone is
// authorised — inside the bare sign-in card.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, page string, status int, data pageData) {
	tmpl, ok := h.pages[page]
	if !ok {
		h.logger.ErrorContext(r.Context(), "unknown template", "page", page)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}

	layout := "layout"
	if data.Admin == nil {
		layout = "auth-layout"
	}
	h.write(w, r, tmpl, layout, status, data)
}

// renderFragment writes one piece of the page for the admin script.
func (h *Handler) renderFragment(w http.ResponseWriter, r *http.Request, name string, status int, data any) {
	h.write(w, r, h.fragments, name, status, data)
}

// write executes a template into a buffer first: a failure halfway through
// would otherwise emit half a response under a success status, which cannot be
// taken back once the header is sent.
func (h *Handler) write(w http.ResponseWriter, r *http.Request, tmpl *template.Template, name string, status int, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.ErrorContext(r.Context(), "render template", "template", name, "err", err)
		http.Error(w, "could not render the page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	// Responses reflect mutable state and may carry a one-time secret.
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		h.logger.ErrorContext(r.Context(), "write response", "template", name, "err", err)
	}
}

// renderError reports a failure in the form the requester can display: an
// alert for the admin script, a whole page for a browser navigation.
func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, status int, title, message string) {
	if isFragment(r) {
		h.renderFragment(w, r, "alert", status, alertData{Title: title, Message: message})
		return
	}
	data := h.newPageData(w, r, admin, title)
	data.Error = message
	h.render(w, r, "error", status, data)
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin) {
	h.renderError(w, r, admin, http.StatusNotFound, "Not found",
		"No such application. It may have been deleted.")
}

// internalError logs the cause and shows the administrator a generic message:
// the detail belongs in the log, not in the browser.
func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, what string, err error) {
	h.logger.ErrorContext(r.Context(), fmt.Sprintf("admin: %s", what), "err", err, "path", r.URL.Path)
	h.renderError(w, r, admin, http.StatusInternalServerError, "Something went wrong",
		"The request could not be completed. Check the server logs for details.")
}
