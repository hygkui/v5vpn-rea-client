package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestWriteLoginResultAuthCodes(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "password expired",
			err:        &protocol.AuthError{Kind: protocol.AuthKindPasswordExpired, Code: "0x100", Msg: "口令过期"},
			wantStatus: http.StatusConflict,
			wantCode:   "password_expired",
		},
		{
			name:       "bad credentials",
			err:        &protocol.AuthError{Kind: protocol.AuthKindBadCredentials, Code: "0x101", Msg: "用户名或密码错误"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "bad_credentials",
		},
		{
			name:       "verify code required",
			err:        &protocol.AuthError{Kind: protocol.AuthKindVerifyCode, Code: "0x66600011"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "verify_code",
		},
		{
			name:       "non-auth error",
			err:        errors.New("network down"),
			wantStatus: http.StatusBadRequest,
			wantCode:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeLoginResult(rec, nil, tc.err)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			var payload map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("invalid JSON response: %v", err)
			}
			if got := payload["code"]; got != tc.wantCode {
				t.Fatalf("code = %q, want %q", got, tc.wantCode)
			}
			if payload["error"] == "" {
				t.Fatal("missing error message")
			}
		})
	}
}
