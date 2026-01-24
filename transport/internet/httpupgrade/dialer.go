package httpupgrade

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type ConnRF struct {
	net.Conn
	Req   *http.Request
	First bool
}

func (c *ConnRF) Read(b []byte) (int, error) {
	if c.First {
		c.First = false
		reader := bufio.NewReaderSize(c.Conn, len(b))
		resp, err := http.ReadResponse(reader, c.Req)
		if err != nil {
			return 0, err
		}
		if resp.Status != "101 Switching Protocols" ||
			strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" ||
			strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
			return 0, errors.New("unrecognized reply")
		}
		return reader.Read(b[:reader.Buffered()])
	}
	return c.Conn.Read(b)
}

// parsePayloadPath extracts payload with [split] support
func parsePayloadPath(path string, configHost string) (actualPath string, initialPayload string, upgradePayload string, customHeaders map[string]string) {
	customHeaders = make(map[string]string)

	// Check if path contains payload markers
	if !strings.Contains(path, "[crlf]") {
		return path, "", "", customHeaders
	}

	// Replace [host] with actual host from config
	if configHost != "" {
		path = strings.ReplaceAll(path, "[host]", configHost)
	}

	// Remove leading / if present (from normalization)
	if strings.HasPrefix(path, "/GET ") || strings.HasPrefix(path, "/POST ") ||
		strings.HasPrefix(path, "/PUT ") || strings.HasPrefix(path, "/HEAD ") ||
		strings.HasPrefix(path, "/CF-RAY ") {
		path = path[1:]
	}

	// Replace markers
	processed := strings.ReplaceAll(path, "[crlf]", "\r\n")
	processed = strings.ReplaceAll(processed, "[lf]", "\n")
	processed = strings.ReplaceAll(processed, "[cr]", "\r")

	// Check for [split]
	if !strings.Contains(processed, "[split]") {
		// No split - return as normal path
		return path, "", "", customHeaders
	}

	// Split payload into initial and upgrade parts
	parts := strings.SplitN(processed, "[split]", 2)
	if len(parts) != 2 {
		return path, "", "", customHeaders
	}

	initialPayload = parts[0]
	upgradePayload = parts[1]

	// Extract path and headers from upgrade request
	lines := strings.Split(upgradePayload, "\r\n")
	actualPath = "/"

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for path in lines like "GET /path" or "CF-RAY /path"
		if strings.Contains(line, " /") && strings.Contains(line, " HTTP/") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasPrefix(field, "/") {
					actualPath = field
					break
				}
			}
		} else if strings.Contains(line, ":") && !strings.Contains(line, " HTTP/") {
			// Extract headers
			headerParts := strings.SplitN(line, ":", 2)
			if len(headerParts) == 2 {
				key := strings.TrimSpace(headerParts[0])
				value := strings.TrimSpace(headerParts[1])
				if key != "" && value != "" {
					customHeaders[key] = value
				}
			}
		}
	}

	return actualPath, initialPayload, upgradePayload, customHeaders
}

// sendInitialPayload sends the initial payload before WebSocket upgrade
func sendInitialPayload(ctx context.Context, conn net.Conn, payload string) error {
	if payload == "" {
		return nil
	}

	errors.LogDebug(ctx, "httpupgrade: sending initial payload")

	// Send the payload
	_, err := conn.Write([]byte(payload))
	if err != nil {
		return errors.New("failed to write initial payload").Base(err)
	}

	// Read and consume the response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, 16384)
	totalRead := 0

	for {
		n, err := conn.Read(buffer[totalRead:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			if err == io.EOF {
				break
			}
			break
		}

		totalRead += n
		response := string(buffer[:totalRead])

		// Check if we have complete response
		if strings.Contains(response, "\r\n\r\n") {
			if strings.Contains(response, "Transfer-Encoding: chunked") {
				if strings.Contains(response, "\r\n0\r\n\r\n") {
					break
				}
			} else if strings.Contains(response, "Content-Length:") {
				if totalRead > 1024 {
					break
				}
			} else {
				if totalRead > 512 {
					break
				}
			}
		}

		if totalRead >= 16000 {
			break
		}
	}

	errors.LogDebug(ctx, "httpupgrade: initial payload complete, received ", totalRead, " bytes")
	return nil
}

func dialhttpUpgrade(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	transportConfiguration := streamSettings.ProtocolSettings.(*Config)

	pconn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to dial to ", dest)
		return nil, err
	}

	var conn net.Conn
	var requestURL url.URL
	tConfig := tls.ConfigFromStreamSettings(streamSettings)

	// Parse path for payload injection, pass config host for [host] replacement
	rawPath := transportConfiguration.GetNormalizedPath()
	actualPath, initialPayload, upgradePayload, customHeaders := parsePayloadPath(rawPath, transportConfiguration.Host)

	errors.LogDebug(ctx, "httpupgrade: path=", actualPath, ", has_payload=", initialPayload != "")

	// Send initial payload BEFORE TLS handshake (if no TLS)
	if tConfig == nil && initialPayload != "" {
		err = sendInitialPayload(ctx, pconn, initialPayload)
		if err != nil {
			pconn.Close()
			return nil, err
		}
	}

	// Setup TLS if configured
	if tConfig != nil {
		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
			conn = tls.UClient(pconn, tlsConfig, fingerprint)
			if err := conn.(*tls.UConn).WebsocketHandshakeContext(ctx); err != nil {
				return nil, err
			}
		} else {
			conn = tls.Client(pconn, tlsConfig)
		}
		requestURL.Scheme = "https"

		// Send initial payload AFTER TLS handshake
		if initialPayload != "" {
			err = sendInitialPayload(ctx, conn, initialPayload)
			if err != nil {
				conn.Close()
				return nil, err
			}
		}
	} else {
		conn = pconn
		requestURL.Scheme = "http"
	}

	// If we have custom upgrade payload, send it directly
	if upgradePayload != "" {
		errors.LogDebug(ctx, "httpupgrade: sending custom upgrade payload")
		_, err = conn.Write([]byte(upgradePayload))
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to write custom upgrade payload")
			return nil, err
		}

		// Create a dummy request for ConnRF to read the response
		requestURL.Host = transportConfiguration.Host
		if requestURL.Host == "" {
			requestURL.Host = dest.Address.String()
		}
		requestURL.Path = actualPath

		req := &http.Request{
			Method: http.MethodGet,
			URL:    &requestURL,
			Header: make(http.Header),
		}

		connRF := &ConnRF{
			Conn:  conn,
			Req:   req,
			First: true,
		}

		if transportConfiguration.Ed == 0 {
			_, err = connRF.Read([]byte{})
			if err != nil {
				return nil, err
			}
		}

		return connRF, nil
	}

	// Build standard WebSocket upgrade request
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" && tConfig != nil {
		requestURL.Host = tConfig.ServerName
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.Address.String()
	}
	requestURL.Path = actualPath

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &requestURL,
		Header: make(http.Header),
	}

	// Add default headers from config
	for key, value := range transportConfiguration.Header {
		AddHeader(req.Header, key, value)
	}

	// Add/override with custom headers from payload
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Set upgrade headers
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "Upgrade")
	}
	if req.Header.Get("Upgrade") == "" {
		req.Header.Set("Upgrade", "websocket")
	}

	// Override Host if specified in custom headers
	if hostHeader, exists := customHeaders["Host"]; exists {
		req.Host = hostHeader
		req.Header.Set("Host", hostHeader)
	}

	// Send WebSocket upgrade request
	err = req.Write(conn)
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to write upgrade request")
		return nil, err
	}

	// Wait for 101 Switching Protocols response
	connRF := &ConnRF{
		Conn:  conn,
		Req:   req,
		First: true,
	}

	if transportConfiguration.Ed == 0 {
		_, err = connRF.Read([]byte{})
		if err != nil {
			return nil, err
		}
	}

	return connRF, nil
}

func AddHeader(header http.Header, key, value string) {
	header[key] = append(header[key], value)
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)

	conn, err := dialhttpUpgrade(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("failed to dial request to ", dest).Base(err)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
