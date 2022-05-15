package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"errors"
	"github.com/carolosf/go-clamd"
	"io"
	"log"
	"net/http"
	"net/url"
)

func main() {}

func init() {
	log.Println(string(ModifierRegisterer), "loaded plugin")
}

// ModifierRegisterer is the symbol the plugin loader will be looking for. It must
// implement the plugin.Registerer interface
// https://github.com/luraproject/lura/blob/master/proxy/plugin/modifier.go#L71
var ModifierRegisterer = registerer("krakend-clamav")

type registerer string

// RegisterModifiers is the function the plugin loader will call to register the
// modifier(s) contained in the plugin using the function passed as argument.
// f will register the factoryFunc under the name and mark it as a request
// and/or response modifier.
func (r registerer) RegisterModifiers(f func(
	name string,
	factoryFunc func(map[string]interface{}) func(interface{}) (interface{}, error),
	appliesToRequest bool,
	appliesToResponse bool,
)) {
	f(string(r)+"-request", r.requestDump, true, false)
	f(string(r)+"-response", r.responseDump, false, true)
	log.Println(string(r), "registered plugin")
}

var unkownTypeErr = errors.New("unknow request type")

func (r registerer) requestDump(
	cfg map[string]interface{},
) func(interface{}) (interface{}, error) {
	// return the modifier
	log.Println("request dumper injected!!!")
	return func(input interface{}) (interface{}, error) {
		req, ok := input.(RequestWrapper)
		if !ok {
			return nil, unkownTypeErr
		}

		log.Println("intercepting request")
		log.Println("url:", req.URL())
		log.Println("method:", req.Method())
		log.Println("headers:", req.Headers())
		log.Println("params:", req.Params())
		log.Println("query:", req.Query())
		log.Println("path:", req.Path())

		log.Println("request", cfg)
		relCfg := cfg["krakend-clamav"].(map[string]interface{})
		clamdAddress, ok := relCfg["clamd_address"].(string)
		if !ok {
			log.Println("Must enter a clamd address")
			return nil, unkownTypeErr
		}

		c := clamd.NewClamd(clamdAddress)

		scanMetadata, scanBody, scanFormFiles := getScanConfig(relCfg)

		request, err := convertToHttpRequest(req)
		if err != nil {
			log.Println("could not convert to http request")
			return nil, errors.New("could not convert to http request")
		}

		if scanFormFiles && parseAndScanHttpFormFiles(request, c) {
			return nil, errors.New("virus found in form body file")
		}

		log.Println("Scan body")
		body, _, _ := drainBody(request.Body)
		if scanBody && body != nil && virusScan(c, body) {
			log.Println("virus found in body")
			return nil, errors.New("virus found in body")
		}

		log.Println("Scan metadata")
		metadata, _ := encodeMetadataAsBytes(req)
		if err != nil {
			log.Println("encode error:", err)
			return nil, errors.New("could not convert metadata")
		}
		if scanMetadata && virusScan(c, bytes.NewReader(metadata.Bytes())) {
			log.Println("virus found in metadata")
			return nil, errors.New("virus found in metadata")
		}

		//convertRequestForModification(req)
		return input, nil
	}
}

func getScanConfig(cfg map[string]interface{}) (bool, bool, bool) {
	scanMetadata := true
	scanMetadata, _ = cfg["scan_metadata"].(bool)

	scanBody := true
	scanBody, _ = cfg["scan_body"].(bool)

	scanFormFiles := true
	scanFormFiles, _ = cfg["scan_form_files"].(bool)

	return scanMetadata, scanBody, scanFormFiles
}

func convertRequestForModification(req RequestWrapper) requestWrapper {
	return requestWrapper{
		req.Method(),
		req.URL(),
		req.Query(),
		req.Path(),
		req.Body(),
		req.Params(),
		req.Headers(),
	}
}

func parseAndScanHttpFormFiles(request *http.Request, c *clamd.Clamd) bool {
	err := request.ParseMultipartForm(200000)
	if err != nil {
		log.Println("no http form")
	} else {
		log.Println("scanning http form")
		form := request.MultipartForm
		for i, _ := range form.File {
			files := form.File[i]
			for j, _ := range files {
				file, err := files[j].Open()
				defer file.Close()
				if err != nil {
					break
				}

				if virusScan(c, bufio.NewReader(file)) {
					log.Println("virus found in form body file")
					return true
				}
			}
		}
	}
	return false
}

func convertToHttpRequest(req RequestWrapper) (*http.Request, error) {
	request, err := http.NewRequest(req.Method(), "http://localhost:8080", req.Body())
	if err != nil {
		return nil, err
	}
	for k, y := range req.Headers() {
		for _, v := range y {
			request.Header.Add(k, v)
		}
	}
	return request, nil
}

func encodeMetadataAsBytes(req RequestWrapper) (bytes.Buffer, error) {
	var metadata bytes.Buffer
	enc := gob.NewEncoder(&metadata)
	err := enc.Encode(requestMetadataWrapper{
		req.Method(),
		req.URL(),
		req.Query(),
		req.Path(),
		req.Params(),
		req.Headers(),
	})
	return metadata, err
}

func virusScan(c *clamd.Clamd, reader io.Reader) bool {
	response, err := c.ScanStream(reader, make(chan bool))
	for s := range response {
		log.Printf("%v %v\n", s, err)
	}

	if parseClamdScanResult(err, response) {
		log.Printf("Virus found!!!")
		return true
	}
	return false
}

func parseClamdScanResult(err error, response chan *clamd.ScanResult) bool {
	if err != nil {
		log.Println("ClamD ScanStream error")
		return true
	} else {
		for s := range response {
			if s.Status != clamd.RES_OK {
				return false
			}
		}
	}

	return true
}

func (r registerer) responseDump(
	cfg map[string]interface{},
) func(interface{}) (interface{}, error) {
	// return the modifier
	log.Println("response dumper injected!!!")
	return func(input interface{}) (interface{}, error) {
		resp, ok := input.(ResponseWrapper)
		if !ok {
			return nil, unkownTypeErr
		}

		log.Println("response", cfg)
		relCfg := cfg["krakend-clamav"].(map[string]interface{})
		clamdAddress, ok := relCfg["clamd_address"].(string)
		if !ok {
			log.Println("Must enter a clamd address")
			return nil, unkownTypeErr
		}
		c := clamd.NewClamd(clamdAddress)

		scanMetadata, scanBody, _ := getScanConfig(relCfg)

		log.Println("intercepting response")
		log.Println("is complete:", resp.IsComplete())
		log.Println("headers:", resp.Headers())
		log.Println("status code:", resp.StatusCode())
		//log.Println("data:", resp.Data())

		log.Println("Scan body")

		if scanBody && virusScan(c, resp.Io()) {
			log.Println("virus found in body")
			return nil, errors.New("virus found in body")
		}

		log.Println("Scan metadata")
		metadata, err := encodeResponseMetadataAsBytes(resp)
		if err != nil {
			log.Println("encode error:", err)
			return nil, errors.New("could not convert response metadata")
		}
		if scanMetadata && virusScan(c, bytes.NewReader(metadata.Bytes())) {
			log.Println("virus found in metadata")
			return nil, errors.New("virus found in metadata")
		}

		//tmp := convertResponseForModification(resp)
		return input, nil
	}
}

func encodeResponseMetadataAsBytes(resp ResponseWrapper) (bytes.Buffer, error) {
	var metadata bytes.Buffer
	enc := gob.NewEncoder(&metadata)
	err := enc.Encode(ResponseMetadataWrapper{
		resp.Headers(),
		resp.StatusCode(),
	})
	return metadata, err
}

func convertResponseForModification(resp ResponseWrapper) responseWrapper {
	return responseWrapper{
		data:       resp.Data(),
		isComplete: resp.IsComplete(),
		metadata: metadataWrapper{
			headers:    resp.Headers(),
			statusCode: resp.StatusCode(),
		},
		io: resp.Io(),
	}
}

// RequestWrapper is an interface for passing proxy request between the lura pipe and the loaded plugins
type RequestWrapper interface {
	Params() map[string]string
	Headers() map[string][]string
	Body() io.ReadCloser
	Method() string
	URL() *url.URL
	Query() url.Values
	Path() string
}

// ResponseWrapper is an interface for passing proxy response between the lura pipe and the loaded plugins
type ResponseWrapper interface {
	Data() map[string]interface{}
	Io() io.Reader
	IsComplete() bool
	Headers() map[string][]string
	StatusCode() int
}

type requestMetadataWrapper struct {
	Method  string
	Url     *url.URL
	Query   url.Values
	Path    string
	Params  map[string]string
	Headers map[string][]string
}

type requestWrapper struct {
	method  string
	url     *url.URL
	query   url.Values
	path    string
	body    io.ReadCloser
	params  map[string]string
	headers map[string][]string
}

func (r *requestWrapper) Method() string               { return r.method }
func (r *requestWrapper) URL() *url.URL                { return r.url }
func (r *requestWrapper) Query() url.Values            { return r.query }
func (r *requestWrapper) Path() string                 { return r.path }
func (r *requestWrapper) Body() io.ReadCloser          { return r.body }
func (r *requestWrapper) Params() map[string]string    { return r.params }
func (r *requestWrapper) Headers() map[string][]string { return r.headers }

func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err = b.Close(); err != nil {
		return nil, b, err
	}
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

type metadataWrapper struct {
	headers    map[string][]string
	statusCode int
}

type ResponseMetadataWrapper struct {
	Headers    map[string][]string
	StatusCode int
}

func (m metadataWrapper) Headers() map[string][]string { return m.headers }
func (m metadataWrapper) StatusCode() int              { return m.statusCode }

type responseWrapper struct {
	data       map[string]interface{}
	isComplete bool
	metadata   metadataWrapper
	io         io.Reader
}

func (r responseWrapper) Data() map[string]interface{} { return r.data }
func (r responseWrapper) IsComplete() bool             { return r.isComplete }
func (r responseWrapper) Io() io.Reader                { return r.io }
func (r responseWrapper) Headers() map[string][]string { return r.metadata.headers }
func (r responseWrapper) StatusCode() int              { return r.metadata.statusCode }
