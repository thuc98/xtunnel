package tunnel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

const (
	StreamTypeConnect = ""

	StreamTypeBind = "bind"
)

type StreamRequest struct {
	Type      string `json:"type,omitempty"`
	Protocol  string `json:"protocol"`
	Target    string `json:"target,omitempty"`
	Port      int    `json:"port,omitempty"`
	SecretKey string `json:"secret_key"`
}

type BindResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type ReverseStreamHeader struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func WriteStreamRequest(w io.Writer, req StreamRequest) error {
	return writeJSONLine(w, req)
}

func ReadStreamRequest(r io.Reader) (StreamRequest, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	var req StreamRequest
	if err := readJSONLine(br, &req); err != nil {
		return StreamRequest{}, nil, fmt.Errorf("stream request: %w", err)
	}
	if req.Protocol == "" {
		return StreamRequest{}, nil, fmt.Errorf("invalid stream request")
	}
	switch req.Type {
	case StreamTypeConnect:
		if req.Target == "" {
			return StreamRequest{}, nil, fmt.Errorf("invalid stream request")
		}
	case StreamTypeBind:
		if req.Port <= 0 || req.Port > 65535 {
			return StreamRequest{}, nil, fmt.Errorf("invalid bind port %d", req.Port)
		}
	default:
		return StreamRequest{}, nil, fmt.Errorf("unsupported stream type %q", req.Type)
	}
	return req, br, nil
}

func WriteBindResponse(w io.Writer, resp BindResponse) error {
	return writeJSONLine(w, resp)
}

func ReadBindResponse(br *bufio.Reader) (BindResponse, error) {
	var resp BindResponse
	if err := readJSONLine(br, &resp); err != nil {
		return BindResponse{}, fmt.Errorf("bind response: %w", err)
	}
	return resp, nil
}

func WriteReverseStreamHeader(w io.Writer, header ReverseStreamHeader) error {
	return writeJSONLine(w, header)
}

func ReadReverseStreamHeader(r io.Reader) (ReverseStreamHeader, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	var header ReverseStreamHeader
	if err := readJSONLine(br, &header); err != nil {
		return ReverseStreamHeader{}, nil, fmt.Errorf("reverse stream header: %w", err)
	}
	return header, br, nil
}

func writeJSONLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func readJSONLine(br *bufio.Reader, v any) error {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
