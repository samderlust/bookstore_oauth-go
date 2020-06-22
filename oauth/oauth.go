package oauth

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/samderlust/bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic    = "X-Public"
	headerXClienId   = "X-Client-Id"
	headerXCallerId  = "X-User-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhoast:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   string `json:"userId"`
	ClientID string `json:"clientId"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetIdInRequest(strKey string, request *http.Request) int64 {
	if request == nil {
		return 0
	}
	id, err := strconv.ParseInt(request.Header.Get(strKey), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	token := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if token == "" {
		return nil
	}
	at, err := getAccessToken(token)
	if err != nil {
		return err
	}
	request.Header.Add(headerXCallerId, at.UserID)
	request.Header.Add(headerXClienId, at.ClientID)

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClienId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(token string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get("oauth/access_token/" + token)

	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to get accesstoken")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get accesstoken")
		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal token")
	}
	return &at, nil
}
