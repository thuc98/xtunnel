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

type StreamRequest struct {
	Protocol  string `json:"protocol"`
	Target    string `json:"target"`
	SecretKey string `json:"secret_key"`
}

func WriteStreamRequest(w io.Writer, req StreamRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func ReadStreamRequest(r io.Reader) (StreamRequest, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return StreamRequest{}, nil, fmt.Errorf("read stream request: %w", err)
	}

	var req StreamRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return StreamRequest{}, nil, fmt.Errorf("decode stream request: %w", err)
	}
	if req.Protocol == "" || req.Target == "" {
		return StreamRequest{}, nil, fmt.Errorf("invalid stream request")
	}
	return req, br, nil
}
