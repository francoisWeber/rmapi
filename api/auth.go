package api

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/juruen/rmapi/config"
	"github.com/juruen/rmapi/log"
	"github.com/juruen/rmapi/model"
	"github.com/juruen/rmapi/transport"
)

const (
	defaultDeviceDesc string = "desktop-linux"
)

func AuthHttpCtx(reAuth, nonInteractive bool) *transport.HttpClientCtx {
	configPath, err := config.ConfigPath()
	if err != nil {
		log.Error.Fatal("failed to get config path")
	}
	authTokens := config.LoadTokens(configPath)
	httpClientCtx := transport.CreateHttpClientCtx(authTokens)

	if authTokens.DeviceToken == "" {
		if nonInteractive {
			log.Error.Fatal("missing token, not asking, aborting")
		}
		// Double-check: if stdin is not available (Docker/container environment), fail fast
		// This prevents infinite loops when readCode() tries to read from empty stdin
		if os.Getenv("RMAPI_SERVER_MODE") != "" || os.Getenv("HOME") == "/home/app" {
			log.Error.Fatal("Cannot read code interactively in server/container mode. Use /api/auth endpoint instead.")
		}
		deviceToken, err := newDeviceToken(&httpClientCtx, readCode())

		if err != nil {
			log.Error.Fatal("failed to crete device token from on-time code")
		}

		log.Trace.Println("device token", deviceToken)

		authTokens.DeviceToken = deviceToken
		httpClientCtx.Tokens.DeviceToken = deviceToken

		config.SaveTokens(configPath, authTokens)
	}

	if authTokens.UserToken == "" || reAuth {
		userToken, err := newUserToken(&httpClientCtx)

		if err == transport.ErrUnauthorized {
			log.Trace.Println("Invalid deviceToken, resetting")
			authTokens.DeviceToken = ""
		} else if err != nil {
			log.Error.Fatalln("failed to create user token from device token", err)
		}

		log.Trace.Println("user token:", userToken)

		authTokens.UserToken = userToken
		httpClientCtx.Tokens.UserToken = userToken

		config.SaveTokens(configPath, authTokens)
	}

	return &httpClientCtx
}

func readCode() string {
	return readCodeWithRetry(0)
}

func readCodeWithRetry(retryCount int) string {
	const maxRetries = 3
	
	if retryCount >= maxRetries {
		log.Error.Fatal("Failed to read valid code after multiple attempts. Aborting.")
		return ""
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter one-time code (go to https://my.remarkable.com/device/browser/connect): ")
	code, err := reader.ReadString('\n')
	
	// If we can't read from stdin or get EOF, fail immediately
	if err != nil || code == "" {
		log.Error.Fatal("Cannot read code interactively: stdin is not available or empty. Use server mode API endpoint /api/auth instead.")
		return ""
	}

	code = strings.TrimSuffix(code, "\n")
	code = strings.TrimSuffix(code, "\r")

	// If code is empty after trimming, it means stdin had just newlines (common in Docker)
	if code == "" {
		if retryCount == 0 {
			log.Error.Println("Received empty input from stdin. This usually means stdin is not connected to a terminal.")
			log.Error.Println("If running in Docker/server mode, use the /api/auth endpoint instead of interactive authentication.")
		}
		log.Error.Fatal("Cannot read code interactively: stdin is not a terminal. Use server mode API endpoint /api/auth instead.")
		return ""
	}

	if len(code) != 8 {
		log.Error.Printf("Code has the wrong length, it should be 8 (got %d characters: %q). Attempt %d/%d", len(code), code, retryCount+1, maxRetries)
		return readCodeWithRetry(retryCount + 1)
	}

	return code
}

func newDeviceToken(http *transport.HttpClientCtx, code string) (string, error) {
	uuid := uuid.New()

	req := model.DeviceTokenRequest{code, defaultDeviceDesc, uuid.String()}

	resp := transport.BodyString{}
	err := http.Post(transport.EmptyBearer, config.NewTokenDevice, req, &resp)

	if err != nil {
		log.Error.Fatal("failed to create a new device token")
		return "", err
	}

	return resp.Content, nil
}

func newUserToken(http *transport.HttpClientCtx) (string, error) {
	resp := transport.BodyString{}
	err := http.Post(transport.DeviceBearer, config.NewUserDevice, nil, &resp)

	if err != nil {
		return "", err
	}

	return resp.Content, nil
}

// NewDeviceToken creates a device token from a one-time code (public API for server mode)
func NewDeviceToken(http *transport.HttpClientCtx, code string) (string, error) {
	return newDeviceToken(http, code)
}

// NewUserToken creates a user token from a device token (public API for server mode)
func NewUserToken(http *transport.HttpClientCtx) (string, error) {
	return newUserToken(http)
}
