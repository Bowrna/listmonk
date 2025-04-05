package main

import (
	"bytes"
	"net/http"
	"net/url"
	"path"
	"regexp"

	"github.com/knadh/listmonk/internal/auth"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	// stdInputMaxLen is the maximum allowed length for a standard input field.
	stdInputMaxLen = 2000

	// URIs.
	uriAdmin = "/admin"
)

type okResp struct {
	Data any `json:"data"`
}

var (
	reUUID = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
)

// registerHandlers registers HTTP handlers.
func initHTTPHandlers(e *echo.Echo, a *App) {
	// Default error handler.
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		// Generic, non-echo error. Log it.
		if _, ok := err.(*echo.HTTPError); !ok {
			a.log.Println(err.Error())
		}
		e.DefaultHTTPErrorHandler(err, c)
	}

	// =================================================================
	// Authenticated non /api handlers.
	{
		// Attach a middleware to the group that checks for auth.
		g := e.Group("", a.auth.Middleware, func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				u := c.Get(auth.UserHTTPCtxKey)

				// On no-auth, redirect to login page
				if _, ok := u.(*echo.HTTPError); ok {
					u, _ := url.Parse(a.urlCfg.LoginURL)
					q := url.Values{}
					q.Set("next", c.Request().RequestURI)
					u.RawQuery = q.Encode()
					return c.Redirect(http.StatusTemporaryRedirect, u.String())
				}

				return next(c)
			}
		})

		// Authenticated endpoints.
		g.GET(path.Join(uriAdmin, ""), a.AdminPage)
		g.GET(path.Join(uriAdmin, "/custom.css"), serveCustomAppearance("admin.custom_css"))
		g.GET(path.Join(uriAdmin, "/custom.js"), serveCustomAppearance("admin.custom_js"))
		g.GET(path.Join(uriAdmin, "/*"), a.AdminPage)
	}

	// =================================================================
	// Authenticated /api/* handlers.
	{
		var (
			// Permission check middleware.
			pm = a.auth.Perm

			// Attach a middleware to the group that checks for auth.
			g = e.Group("", a.auth.Middleware, func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error {
					u := c.Get(auth.UserHTTPCtxKey)

					// On no-auth, respond with a JSON error.
					if err, ok := u.(*echo.HTTPError); ok {
						return err
					}

					return next(c)
				}
			})
		)

		// API endpoints.
		g.GET("/api/health", a.HealthCheck)
		g.GET("/api/config", a.GetServerConfig)
		g.GET("/api/lang/:lang", a.GetI18nLang)
		g.GET("/api/dashboard/charts", a.GetDashboardCharts)
		g.GET("/api/dashboard/counts", a.GetDashboardCounts)

		g.GET("/api/settings", pm(a.GetSettings, "settings:get"))
		g.PUT("/api/settings", pm(a.UpdateSettings, "settings:manage"))
		g.POST("/api/settings/smtp/test", pm(a.TestSMTPSettings, "settings:manage"))
		g.POST("/api/admin/reload", pm(a.ReloadApp, "settings:manage"))
		g.GET("/api/logs", pm(a.GetLogs, "settings:get"))
		g.GET("/api/events", pm(a.EventStream, "settings:get"))
		g.GET("/api/about", a.GetAboutInfo)

		g.GET("/api/subscribers", pm(a.QuerySubscribers, "subscribers:get_all", "subscribers:get"))
		g.GET("/api/subscribers/:id", pm(a.GetSubscriber, "subscribers:get_all", "subscribers:get"))
		g.GET("/api/subscribers/:id/export", pm(a.ExportSubscriberData, "subscribers:get_all", "subscribers:get"))
		g.GET("/api/subscribers/:id/bounces", pm(a.GetSubscriberBounces, "bounces:get"))
		g.DELETE("/api/subscribers/:id/bounces", pm(a.DeleteSubscriberBounces, "bounces:manage"))
		g.POST("/api/subscribers", pm(a.CreateSubscriber, "subscribers:manage"))
		g.PUT("/api/subscribers/:id", pm(a.UpdateSubscriber, "subscribers:manage"))
		g.POST("/api/subscribers/:id/optin", pm(a.SubscriberSendOptin, "subscribers:manage"))
		g.PUT("/api/subscribers/blocklist", pm(a.BlocklistSubscribers, "subscribers:manage"))
		g.PUT("/api/subscribers/:id/blocklist", pm(a.BlocklistSubscribers, "subscribers:manage"))
		g.PUT("/api/subscribers/lists/:id", pm(a.ManageSubscriberLists, "subscribers:manage"))
		g.PUT("/api/subscribers/lists", pm(a.ManageSubscriberLists, "subscribers:manage"))
		g.DELETE("/api/subscribers/:id", pm(a.DeleteSubscribers, "subscribers:manage"))
		g.DELETE("/api/subscribers", pm(a.DeleteSubscribers, "subscribers:manage"))

		g.GET("/api/bounces", pm(a.GetBounces, "bounces:get"))
		g.GET("/api/bounces/:id", pm(a.GetBounces, "bounces:get"))
		g.DELETE("/api/bounces", pm(a.DeleteBounces, "bounces:manage"))
		g.DELETE("/api/bounces/:id", pm(a.DeleteBounces, "bounces:manage"))

		// Subscriber operations based on arbitrary SQL queries.
		// These aren't very REST-like.
		g.POST("/api/subscribers/query/delete", pm(a.DeleteSubscribersByQuery, "subscribers:manage"))
		g.PUT("/api/subscribers/query/blocklist", pm(a.BlocklistSubscribersByQuery, "subscribers:manage"))
		g.PUT("/api/subscribers/query/lists", pm(a.ManageSubscriberListsByQuery, "subscribers:manage"))
		g.GET("/api/subscribers/export",
			pm(middleware.GzipWithConfig(middleware.GzipConfig{Level: 9})(a.ExportSubscribers), "subscribers:get_all", "subscribers:get"))

		g.GET("/api/import/subscribers", pm(a.GetImportSubscribers, "subscribers:import"))
		g.GET("/api/import/subscribers/logs", pm(a.GetImportSubscriberStats, "subscribers:import"))
		g.POST("/api/import/subscribers", pm(a.ImportSubscribers, "subscribers:import"))
		g.DELETE("/api/import/subscribers", pm(a.StopImportSubscribers, "subscribers:import"))

		// Individual list permissions are applied directly within handleGetLists.
		g.GET("/api/lists", a.GetLists)
		g.GET("/api/lists/:id", a.GetList)
		g.POST("/api/lists", pm(a.CreateList, "lists:manage_all"))
		g.PUT("/api/lists/:id", a.UpdateList)
		g.DELETE("/api/lists/:id", a.DeleteLists)

		g.GET("/api/campaigns", pm(a.GetCampaigns, "campaigns:get_all", "campaigns:get"))
		g.GET("/api/campaigns/running/stats", pm(a.GetRunningCampaignStats, "campaigns:get_all", "campaigns:get"))
		g.GET("/api/campaigns/:id", pm(a.GetCampaign, "campaigns:get_all", "campaigns:get"))
		g.GET("/api/campaigns/analytics/:type", pm(a.GetCampaignViewAnalytics, "campaigns:get_analytics"))
		g.GET("/api/campaigns/:id/preview", pm(a.PreviewCampaign, "campaigns:get_all", "campaigns:get"))
		g.POST("/api/campaigns/:id/preview", pm(a.PreviewCampaign, "campaigns:get_all", "campaigns:get"))
		g.POST("/api/campaigns/:id/content", pm(a.CampaignContent, "campaigns:manage_all", "campaigns:manage"))
		g.POST("/api/campaigns/:id/text", pm(a.PreviewCampaign, "campaigns:get"))
		g.POST("/api/campaigns/:id/test", pm(a.TestCampaign, "campaigns:manage_all", "campaigns:manage"))
		g.POST("/api/campaigns", pm(a.CreateCampaign, "campaigns:manage_all", "campaigns:manage"))
		g.PUT("/api/campaigns/:id", pm(a.UpdateCampaign, "campaigns:manage_all", "campaigns:manage"))
		g.PUT("/api/campaigns/:id/status", pm(a.UpdateCampaignStatus, "campaigns:manage_all", "campaigns:manage"))
		g.PUT("/api/campaigns/:id/archive", pm(a.UpdateCampaignArchive, "campaigns:manage_all", "campaigns:manage"))
		g.DELETE("/api/campaigns/:id", pm(a.DeleteCampaign, "campaigns:manage_all", "campaigns:manage"))

		g.GET("/api/media", pm(a.GetMedia, "media:get"))
		g.GET("/api/media/:id", pm(a.GetMedia, "media:get"))
		g.POST("/api/media", pm(a.UploadMedia, "media:manage"))
		g.DELETE("/api/media/:id", pm(a.DeleteMedia, "media:manage"))

		g.GET("/api/templates", pm(a.GetTemplates, "templates:get"))
		g.GET("/api/templates/:id", pm(a.GetTemplates, "templates:get"))
		g.GET("/api/templates/:id/preview", pm(a.PreviewTemplate, "templates:get"))
		g.POST("/api/templates/preview", pm(a.PreviewTemplate, "templates:get"))
		g.POST("/api/templates", pm(a.CreateTemplate, "templates:manage"))
		g.PUT("/api/templates/:id", pm(a.UpdateTemplate, "templates:manage"))
		g.PUT("/api/templates/:id/default", pm(a.TemplateSetDefault, "templates:manage"))
		g.DELETE("/api/templates/:id", pm(a.DeleteTemplate, "templates:manage"))

		g.DELETE("/api/maintenance/subscribers/:type", pm(a.GCSubscribers, "settings:maintain"))
		g.DELETE("/api/maintenance/analytics/:type", pm(a.GCCampaignAnalytics, "settings:maintain"))
		g.DELETE("/api/maintenance/subscriptions/unconfirmed", pm(a.GCSubscriptions, "settings:maintain"))

		g.POST("/api/tx", pm(a.SendTxMessage, "tx:send"))

		g.GET("/api/profile", a.GetUserProfile)
		g.PUT("/api/profile", a.UpdateUserProfile)
		g.GET("/api/users", pm(a.GetUsers, "users:get"))
		g.GET("/api/users/:id", pm(a.GetUsers, "users:get"))
		g.POST("/api/users", pm(a.CreateUser, "users:manage"))
		g.PUT("/api/users/:id", pm(a.UpdateUser, "users:manage"))
		g.DELETE("/api/users", pm(a.DeleteUsers, "users:manage"))
		g.DELETE("/api/users/:id", pm(a.DeleteUsers, "users:manage"))
		g.POST("/api/logout", a.Logout)

		g.GET("/api/roles/users", pm(a.GetUserRoles, "roles:get"))
		g.GET("/api/roles/lists", pm(a.GeListRoles, "roles:get"))
		g.POST("/api/roles/users", pm(a.CreateUserRole, "roles:manage"))
		g.POST("/api/roles/lists", pm(a.CreateListRole, "roles:manage"))
		g.PUT("/api/roles/users/:id", pm(a.UpdateUserRole, "roles:manage"))
		g.PUT("/api/roles/lists/:id", pm(a.UpdateListRole, "roles:manage"))
		g.DELETE("/api/roles/:id", pm(a.DeleteRole, "roles:manage"))

		if a.cfg.BounceWebhooksEnabled {
			// Private authenticated bounce endpoint.
			g.POST("/webhooks/bounce", pm(a.BounceWebhook, "webhooks:post_bounce"))
		}
<<<<<<< HEAD
	)

	// Authenticated endpoints.
	a.GET(path.Join(uriAdmin, ""), h.AdminPage)
	a.GET(path.Join(uriAdmin, "/custom.css"), serveCustomAppearance("admin.custom_css"))
	a.GET(path.Join(uriAdmin, "/custom.js"), serveCustomAppearance("admin.custom_js"))
	a.GET(path.Join(uriAdmin, "/*"), h.AdminPage)

	pm := app.auth.Perm

	// API endpoints.
	api.GET("/api/health", h.HealthCheck)
	api.GET("/api/config", h.GetServerConfig)
	api.GET("/api/lang/:lang", h.GetI18nLang)
	api.GET("/api/dashboard/charts", h.GetDashboardCharts)
	api.GET("/api/dashboard/counts", h.GetDashboardCounts)

	api.GET("/api/settings", pm(h.GetSettings, "settings:get"))
	api.PUT("/api/settings", pm(h.UpdateSettings, "settings:manage"))
	api.POST("/api/settings/smtp/test", pm(h.TestSMTPSettings, "settings:manage"))
	api.POST("/api/admin/reload", pm(h.ReloadApp, "settings:manage"))
	api.GET("/api/logs", pm(h.GetLogs, "settings:get"))
	api.GET("/api/events", pm(h.EventStream, "settings:get"))
	api.GET("/api/about", h.GetAboutInfo)

	api.GET("/api/subscribers", pm(h.QuerySubscribers, "subscribers:get_all", "subscribers:get"))
	api.GET("/api/subscribers/:id", pm(h.GetSubscriber, "subscribers:get_all", "subscribers:get"))
	api.GET("/api/subscribers/:id/export", pm(h.ExportSubscriberData, "subscribers:get_all", "subscribers:get"))
	api.GET("/api/subscribers/:id/bounces", pm(h.GetSubscriberBounces, "bounces:get"))
	api.DELETE("/api/subscribers/:id/bounces", pm(h.DeleteSubscriberBounces, "bounces:manage"))
	api.POST("/api/subscribers", pm(h.CreateSubscriber, "subscribers:manage"))
	api.PUT("/api/subscribers/:id", pm(h.UpdateSubscriber, "subscribers:manage"))
	api.POST("/api/subscribers/:id/optin", pm(h.SubscriberSendOptin, "subscribers:manage"))
	api.PUT("/api/subscribers/blocklist", pm(h.BlocklistSubscribers, "subscribers:manage"))
	api.PUT("/api/subscribers/:id/blocklist", pm(h.BlocklistSubscribers, "subscribers:manage"))
	api.PUT("/api/subscribers/lists/:id", pm(h.ManageSubscriberLists, "subscribers:manage"))
	api.PUT("/api/subscribers/lists", pm(h.ManageSubscriberLists, "subscribers:manage"))
	api.DELETE("/api/subscribers/:id", pm(h.DeleteSubscribers, "subscribers:manage"))
	api.DELETE("/api/subscribers", pm(h.DeleteSubscribers, "subscribers:manage"))

<<<<<<< HEAD
	api.GET("/api/bounces", pm(handleGetBounces, "bounces:get"))
	api.GET("/api/bounces/:id", pm(handleGetBounces, "bounces:get"))
	api.DELETE("/api/bounces", pm(handleDeleteBounces, "bounces:manage"))
	api.DELETE("/api/bounces/:id", pm(handleDeleteBounces, "bounces:manage"))
	api.PUT("/api/bounces/blocklist", pm(handleBlocklistSubscriberBounces, "bounces:manage"))
	api.PUT("/api/bounces/:id/blocklist", pm(handleBlocklistSubscriberBounces, "bounces:manage"))
=======
	api.GET("/api/bounces", pm(h.GetBounces, "bounces:get"))
	api.GET("/api/bounces/:id", pm(h.GetBounces, "bounces:get"))
	api.DELETE("/api/bounces", pm(h.DeleteBounces, "bounces:manage"))
	api.DELETE("/api/bounces/:id", pm(h.DeleteBounces, "bounces:manage"))
>>>>>>> 00c858fc (Refactor all HTTP handlers and attach them to a single struct.)

	// Subscriber operations based on arbitrary SQL queries.
	// These aren't very REST-like.
	api.POST("/api/subscribers/query/delete", pm(h.DeleteSubscribersByQuery, "subscribers:manage"))
	api.PUT("/api/subscribers/query/blocklist", pm(h.BlocklistSubscribersByQuery, "subscribers:manage"))
	api.PUT("/api/subscribers/query/lists", pm(h.ManageSubscriberListsByQuery, "subscribers:manage"))
	api.GET("/api/subscribers/export",
		pm(middleware.GzipWithConfig(middleware.GzipConfig{Level: 9})(h.ExportSubscribers), "subscribers:get_all", "subscribers:get"))

	api.GET("/api/import/subscribers", pm(h.GetImportSubscribers, "subscribers:import"))
	api.GET("/api/import/subscribers/logs", pm(h.GetImportSubscriberStats, "subscribers:import"))
	api.POST("/api/import/subscribers", pm(h.ImportSubscribers, "subscribers:import"))
	api.DELETE("/api/import/subscribers", pm(h.StopImportSubscribers, "subscribers:import"))

	// Individual list permissions are applied directly within handleGetLists.
	api.GET("/api/lists", h.GetLists)
	api.GET("/api/lists/:id", h.GetList)
	api.POST("/api/lists", pm(h.CreateList, "lists:manage_all"))
	api.PUT("/api/lists/:id", h.UpdateList)
	api.DELETE("/api/lists/:id", h.DeleteLists)

	api.GET("/api/campaigns", pm(h.GetCampaigns, "campaigns:get_all", "campaigns:get"))
	api.GET("/api/campaigns/running/stats", pm(h.GetRunningCampaignStats, "campaigns:get_all", "campaigns:get"))
	api.GET("/api/campaigns/:id", pm(h.GetCampaign, "campaigns:get_all", "campaigns:get"))
	api.GET("/api/campaigns/analytics/:type", pm(h.GetCampaignViewAnalytics, "campaigns:get_analytics"))
	api.GET("/api/campaigns/:id/preview", pm(h.PreviewCampaign, "campaigns:get_all", "campaigns:get"))
	api.POST("/api/campaigns/:id/preview", pm(h.PreviewCampaign, "campaigns:get_all", "campaigns:get"))
	api.POST("/api/campaigns/:id/content", pm(h.CampaignContent, "campaigns:manage_all", "campaigns:manage"))
	api.POST("/api/campaigns/:id/text", pm(h.PreviewCampaign, "campaigns:get"))
	api.POST("/api/campaigns/:id/test", pm(h.TestCampaign, "campaigns:manage_all", "campaigns:manage"))
	api.POST("/api/campaigns", pm(h.CreateCampaign, "campaigns:manage_all", "campaigns:manage"))
	api.PUT("/api/campaigns/:id", pm(h.UpdateCampaign, "campaigns:manage_all", "campaigns:manage"))
	api.PUT("/api/campaigns/:id/status", pm(h.UpdateCampaignStatus, "campaigns:manage_all", "campaigns:manage"))
	api.PUT("/api/campaigns/:id/archive", pm(h.UpdateCampaignArchive, "campaigns:manage_all", "campaigns:manage"))
	api.DELETE("/api/campaigns/:id", pm(h.DeleteCampaign, "campaigns:manage_all", "campaigns:manage"))

	api.GET("/api/media", pm(h.GetMedia, "media:get"))
	api.GET("/api/media/:id", pm(h.GetMedia, "media:get"))
	api.POST("/api/media", pm(h.UploadMedia, "media:manage"))
	api.DELETE("/api/media/:id", pm(h.DeleteMedia, "media:manage"))

	api.GET("/api/templates", pm(h.GetTemplates, "templates:get"))
	api.GET("/api/templates/:id", pm(h.GetTemplates, "templates:get"))
	api.GET("/api/templates/:id/preview", pm(h.PreviewTemplate, "templates:get"))
	api.POST("/api/templates/preview", pm(h.PreviewTemplate, "templates:get"))
	api.POST("/api/templates", pm(h.CreateTemplate, "templates:manage"))
	api.PUT("/api/templates/:id", pm(h.UpdateTemplate, "templates:manage"))
	api.PUT("/api/templates/:id/default", pm(h.TemplateSetDefault, "templates:manage"))
	api.DELETE("/api/templates/:id", pm(h.DeleteTemplate, "templates:manage"))

	api.DELETE("/api/maintenance/subscribers/:type", pm(h.GCSubscribers, "settings:maintain"))
	api.DELETE("/api/maintenance/analytics/:type", pm(h.GCCampaignAnalytics, "settings:maintain"))
	api.DELETE("/api/maintenance/subscriptions/unconfirmed", pm(h.GCSubscriptions, "settings:maintain"))

	api.POST("/api/tx", pm(h.SendTxMessage, "tx:send"))

	api.GET("/api/profile", h.GetUserProfile)
	api.PUT("/api/profile", h.UpdateUserProfile)
	api.GET("/api/users", pm(h.GetUsers, "users:get"))
	api.GET("/api/users/:id", pm(h.GetUsers, "users:get"))
	api.POST("/api/users", pm(h.CreateUser, "users:manage"))
	api.PUT("/api/users/:id", pm(h.UpdateUser, "users:manage"))
	api.DELETE("/api/users", pm(h.DeleteUsers, "users:manage"))
	api.DELETE("/api/users/:id", pm(h.DeleteUsers, "users:manage"))
	api.POST("/api/logout", h.Logout)

	api.GET("/api/roles/users", pm(h.GetUserRoles, "roles:get"))
	api.GET("/api/roles/lists", pm(h.GeListRoles, "roles:get"))
	api.POST("/api/roles/users", pm(h.CreateUserRole, "roles:manage"))
	api.POST("/api/roles/lists", pm(h.CreateListRole, "roles:manage"))
	api.PUT("/api/roles/users/:id", pm(h.UpdateUserRole, "roles:manage"))
	api.PUT("/api/roles/lists/:id", pm(h.UpdateListRole, "roles:manage"))
	api.DELETE("/api/roles/:id", pm(h.DeleteRole, "roles:manage"))

	if app.constants.BounceWebhooksEnabled {
		// Private authenticated bounce endpoint.
		api.POST("/webhooks/bounce", pm(h.BounceWebhook, "webhooks:post_bounce"))

		// Public bounce endpoints for webservices like SES.
		p.POST("/webhooks/service/:service", h.BounceWebhook)
=======
>>>>>>> e327ebbb (Move all HTTP handlers directly to `App` and remove the redundant in-between layer.)
	}

	// =================================================================
	// Public API endpoints.
	{
		// Public unauthenticated endpoints.
		g := e.Group("")

		if a.cfg.BounceWebhooksEnabled {
			// Public bounce endpoints for webservices like SES.
			g.POST("/webhooks/service/:service", a.BounceWebhook)
		}

		// Landing page.
		g.GET("/", func(c echo.Context) error {
			return c.Render(http.StatusOK, "home", publicTpl{Title: "listmonk"})
		})

		// Public admin endpoints (login page, OIDC endpoints).
		g.GET(path.Join(uriAdmin, "/login"), a.LoginPage)
		g.POST(path.Join(uriAdmin, "/login"), a.LoginPage)

		if a.cfg.Security.OIDC.Enabled {
			g.POST("/auth/oidc", a.OIDCLogin)
			g.GET("/auth/oidc", a.OIDCFinish)
		}

		// Public APIs.
		g.GET("/api/public/lists", a.GetPublicLists)
		g.POST("/api/public/subscription", a.PublicSubscription)
		if a.cfg.EnablePublicArchive {
			g.GET("/api/public/archive", a.GetCampaignArchives)
		}

		// /public/static/* file server is registered in initHTTPServer().
		// Public subscriber facing views.
		g.GET("/subscription/form", a.SubscriptionFormPage)
		g.POST("/subscription/form", a.SubscriptionForm)
		g.GET("/subscription/:campUUID/:subUUID", noIndex(validateUUID(subscriberExists(a.SubscriptionPage), "campUUID", "subUUID")))
		g.POST("/subscription/:campUUID/:subUUID", validateUUID(subscriberExists(a.SubscriptionPrefs), "campUUID", "subUUID"))
		g.GET("/subscription/optin/:subUUID", noIndex(validateUUID(subscriberExists(a.OptinPage), "subUUID")))
		g.POST("/subscription/optin/:subUUID", validateUUID(subscriberExists(a.OptinPage), "subUUID"))
		g.POST("/subscription/export/:subUUID", validateUUID(subscriberExists(a.SelfExportSubscriberData), "subUUID"))
		g.POST("/subscription/wipe/:subUUID", validateUUID(subscriberExists(a.WipeSubscriberData), "subUUID"))
		g.GET("/link/:linkUUID/:campUUID/:subUUID", noIndex(validateUUID(a.LinkRedirect, "linkUUID", "campUUID", "subUUID")))
		g.GET("/campaign/:campUUID/:subUUID", noIndex(validateUUID(a.ViewCampaignMessage, "campUUID", "subUUID")))
		g.GET("/campaign/:campUUID/:subUUID/px.png", noIndex(validateUUID(a.RegisterCampaignView, "campUUID", "subUUID")))

		if a.cfg.EnablePublicArchive {
			g.GET("/archive", a.CampaignArchivesPage)
			g.GET("/archive.xml", a.GetCampaignArchivesFeed)
			g.GET("/archive/:id", a.CampaignArchivePage)
			g.GET("/archive/latest", a.CampaignArchivePageLatest)
		}

		g.GET("/public/custom.css", serveCustomAppearance("public.custom_css"))
		g.GET("/public/custom.js", serveCustomAppearance("public.custom_js"))

		// Public health API endpoint.
		g.GET("/health", a.HealthCheck)

		// 404 pages.
		g.RouteNotFound("/*", func(c echo.Context) error {
			return c.Render(http.StatusNotFound, tplMessage,
				makeMsgTpl("404 - "+a.i18n.T("public.notFoundTitle"), "", ""))
		})
		g.RouteNotFound("/api/*", func(c echo.Context) error {
			return echo.NewHTTPError(http.StatusNotFound, "404 unknown endpoint")
		})
		g.RouteNotFound("/admin/*", func(c echo.Context) error {
			return echo.NewHTTPError(http.StatusNotFound, "404 page not found")
		})
	}
}

// AdminPage is the root handler that renders the Javascript admin frontend.
func (a *App) AdminPage(c echo.Context) error {
	b, err := a.fs.Read(path.Join(uriAdmin, "/index.html"))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	b = bytes.ReplaceAll(b, []byte("asset_version"), []byte(a.cfg.AssetVersion))

	return c.HTMLBlob(http.StatusOK, b)
}

// HealthCheck is a healthcheck endpoint that returns a 200 response.
func (a *App) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, okResp{true})
}

// serveCustomAppearance serves the given custom CSS/JS appearance blob
// meant for customizing public and admin pages from the admin settings UI.
func serveCustomAppearance(name string) echo.HandlerFunc {
	return func(c echo.Context) error {
		var (
			app = c.Get("app").(*App)

			out []byte
			hdr string
		)

		switch name {
		case "admin.custom_css":
			out = app.cfg.Appearance.AdminCSS
			hdr = "text/css; charset=utf-8"

		case "admin.custom_js":
			out = app.cfg.Appearance.AdminJS
			hdr = "application/javascript; charset=utf-8"

		case "public.custom_css":
			out = app.cfg.Appearance.PublicCSS
			hdr = "text/css; charset=utf-8"

		case "public.custom_js":
			out = app.cfg.Appearance.PublicJS
			hdr = "application/javascript; charset=utf-8"
		}

		return c.Blob(http.StatusOK, hdr, out)
	}
}

// validateUUID middleware validates the UUID string format for a given set of params.
func validateUUID(next echo.HandlerFunc, params ...string) echo.HandlerFunc {
	return func(c echo.Context) error {
		app := c.Get("app").(*App)

		for _, p := range params {
			if !reUUID.MatchString(c.Param(p)) {
				return c.Render(http.StatusBadRequest, tplMessage, makeMsgTpl(app.i18n.T("public.errorTitle"), "",
					app.i18n.T("globals.messages.invalidUUID")))
			}
		}
		return next(c)
	}
}

// subscriberExists middleware checks if a subscriber exists given the UUID
// param in a request.
func subscriberExists(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var (
			app     = c.Get("app").(*App)
			subUUID = c.Param("subUUID")
		)

		if _, err := app.core.GetSubscriber(0, subUUID, ""); err != nil {
			if er, ok := err.(*echo.HTTPError); ok && er.Code == http.StatusBadRequest {
				return c.Render(http.StatusNotFound, tplMessage,
					makeMsgTpl(app.i18n.T("public.notFoundTitle"), "", er.Message.(string)))
			}

			app.log.Printf("error checking subscriber existence: %v", err)
			return c.Render(http.StatusInternalServerError, tplMessage,
				makeMsgTpl(app.i18n.T("public.errorTitle"), "", app.i18n.T("public.errorProcessingRequest")))
		}

		return next(c)
	}
}

// noIndex adds the HTTP header requesting robots to not crawl the page.
func noIndex(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("X-Robots-Tag", "noindex")
		return next(c)
	}
}
