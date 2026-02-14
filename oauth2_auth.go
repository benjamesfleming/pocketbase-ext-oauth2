package oauth2

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/benjamesfleming/pocketbase-ext-oauth2/client"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

func api_OAuth2Authorize(e *core.RequestEvent) error {
	r := e.Request
	w := e.Response
	ctx := r.Context()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAuthorizeRequest", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return nil
	}
	// You have now access to authorizeRequest, Code ResponseTypes, Scopes ...

	r.ParseForm()
	token := r.FormValue("token")
	var u *core.Record
	if len(token) > 0 {
		if u, err = e.App.FindAuthRecordByToken(token); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return e.InternalServerError("Internal Error", err)
			}
		}
	}
	if u == nil {
		if ar.GetRequestForm().Get("prompt") == "none" {
			// TODO/conformance: The prompt parameter should be passed to the frontend to allow it to
			//                   make informed decisions about how to handle the login. For example,
			//                   if the prompt=none parameter is provided, the frontend should not
			//                   display any login UI and instead should immediately return an error
			//                   if the user is not authenticated.
			//
			// The "prompt=none" parameter indicates that the Authorization Server MUST NOT
			// display any authentication or consent user interface pages.
			// @ref https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired.WithHint("The prompt=none parameter was provided but the user is not authenticated."))
			return nil
		}
		c, _ := ar.GetClient().(*client.Client)
		state := map[string]interface{}{
			"collection":       GetOAuth2Config().UserCollection,
			"client_id":        c.ID,
			"client_name":      c.Name,
			"client_uri":       c.ClientURI,
			"prompt":           ar.GetRequestForm().Get("prompt"),
			"requested_scopes": ar.GetRequestedScopes(),
			"redirect_uri":     e.App.Settings().Meta.AppURL + r.RequestURI,
		}
		// Base64-URL encode the state to make it safe for URL usage.
		stateBytes, _ := json.Marshal(state)
		stateB64Str := base64.RawURLEncoding.EncodeToString(stateBytes)
		return e.Redirect(http.StatusTemporaryRedirect, e.App.Settings().Meta.AppURL+GetOAuth2Config().PathPrefix+"/login?state="+stateB64Str)
	}

	// Check if the user belongs to the expected collection. This is optional,
	// but it can be a good way to ensure that the login hasn't been tampered
	// with.

	if u.Collection().Name != GetOAuth2Config().UserCollection {
		return e.BadRequestError("Invalid user collection", nil)
	}

	// At this point, the user is authenticated and we can grant the requested scopes.

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	//

	// Now that the user is authorized, we set up a session:
	mySessionData := NewSession(e.App, u.Id, u.Collection().Id)
	// TODO/conformance: The "auth_time" claim should be provided by the frontend to allow for
	//                   proper handling of the "max_age" parameter.
	mySessionData.Claims.AuthTime = time.Now()
	mySessionData.Claims.RequestedAt = ar.GetRequestedAt()

	// When using the HMACSHA strategy you must use something that implements the HMACSessionContainer.
	// It brings you the power of overriding the default values.
	//
	// mySessionData.HMACSession = &strategy.HMACSession{
	//	AccessTokenExpiry: time.Now().Add(time.Day),
	//	AuthorizeCodeExpiry: time.Now().Add(time.Day),
	// }
	//

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

	// It's also wise to check the requested scopes, e.g.:
	// if ar.GetRequestedScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAuthorizeResponse", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return nil
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(ctx, w, ar, response)
	return nil
}
