package main

import (
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/fcgi"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/http/pprof"
	"net/mail"
	"net/rpc"
	"net/rpc/jsonrpc"
	"net/smtp"
	"net/textproto"
	"net/url"
)

func main() {
	var _ = http.StatusVariantAlsoNegotiates
	var _ = cgi.Request
	var _ = fcgi.ErrConnClosed
	var _ = httptest.DefaultRemoteAddr
	var _ = httptrace.ContextClientTrace
	var _ = httputil.DumpRequest
	var _ = pprof.Cmdline
	var _ = mail.ParseAddress
	var _ = rpc.Accept
	var _ = jsonrpc.Dial
	var _ = smtp.Dial
	var _ = textproto.CanonicalMIMEHeaderKey
	var _ = url.Parse
	var _ = net.DefaultResolver
}
