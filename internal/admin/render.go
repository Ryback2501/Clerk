package admin

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Ryback2501/Clerk/internal/adminauth"
	"github.com/Ryback2501/Clerk/internal/web"
)

// newPageData builds the common view model and issues the CSRF token the
// rendered forms will carry.
func (h *Handler) newPageData(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, title string) pageData {
	return pageData{
		Title:     title,
		Admin:     admin,
		Insecure:  h.insecure,
		CSRFToken: h.csrf.Issue(w, r),
		CSRFField: web.CSRFFieldName,
		SignedIn:  admin != nil && h.oauth != nil,
	}
}

// urlQueryEscape escapes a value for use in a query string.
func urlQueryEscape(v string) string { return url.QueryEscape(v) }

// render writes a page. The template is executed into a buffer first: a failure
// halfway through would otherwise emit a half-written page under a 200 status,
// which cannot be taken back once the header is sent.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, page string, status int, data pageData) {
	tmpl, ok := h.pages[page]
	if !ok {
		h.logger.ErrorContext(r.Context(), "unknown template", "page", page)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}

	if data.Admin == nil {
		// Error pages can render before anyone is authenticated; the layout
		// still dereferences this.
		data.Admin = &adminauth.Admin{Name: "Not signed in"}
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.logger.ErrorContext(r.Context(), "render template", "page", page, "err", err)
		http.Error(w, "could not render the page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// The admin UI ships its own stylesheet and runs no scripts, so it can
	// afford a restrictive policy.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	// Pages reflect mutable state and may carry a one-time secret.
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		h.logger.ErrorContext(r.Context(), "write response", "page", page, "err", err)
	}
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, admin *adminauth.Admin, status int, title, message string) {
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

// revealCookie names the cookie carrying the reveal token for one application.
//
// The name is per-application on purpose. A single shared cookie has only one
// slot, so generating a second secret before viewing the first would overwrite
// its token — leaving an application whose previous secret is already
// invalidated and whose new one could never be displayed.
func revealCookie(applicationID int64) string {
	return revealCookiePrefix + strconv.FormatInt(applicationID, 10)
}

// revealOnce stashes a freshly generated secret and hands the browser the
// single-use token that displays it.
func (h *Handler) revealOnce(w http.ResponseWriter, applicationID int64, plainSecret string) {
	token := h.reveal.put(applicationID, plainSecret)
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     revealCookie(applicationID),
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(revealTTL.Seconds()),
	})
}

// takeRevealed consumes the reveal token, if the request carries one, and
// clears the cookie so a reload cannot show the secret again.
func (h *Handler) takeRevealed(w http.ResponseWriter, r *http.Request, applicationID int64) string {
	name := revealCookie(applicationID)

	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return ""
	}

	// Clear it either way: this cookie belongs to this application alone, so
	// once it has been presented there is nothing further it can unlock.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	plain, ok := h.reveal.take(cookie.Value, applicationID)
	if !ok {
		return ""
	}
	return plain
}
