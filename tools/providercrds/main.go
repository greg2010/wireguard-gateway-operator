package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const packagePrefix = "xpkg.upbound.io/upbound/provider-"

var registryClient = &http.Client{Timeout: 2 * time.Minute}

type packageRef struct {
	registry   string
	repository string
	tag        string
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Platform  struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Layers    []descriptor `json:"layers"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	values := flag.String("values", "", "provider values file")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *values == "" || *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: providercrds -values <values.yaml> -out <dir> <crd name>...")
		os.Exit(2)
	}
	if err := run(ctx, *values, *out, flag.Args()); err != nil {
		fail(err)
	}
}

func run(ctx context.Context, values, out string, wanted []string) error {
	refs, tag, err := collectPackages(ctx, values)
	if err != nil {
		return err
	}
	byPackage := map[string][]string{}
	for _, name := range wanted {
		pkg, err := packageForCRD(name)
		if err != nil {
			return err
		}
		byPackage[pkg] = append(byPackage[pkg], name)
	}
	selected := map[string]string{}
	for pkg, names := range byPackage {
		ref, ok := refs[pkg]
		if !ok {
			return fmt.Errorf("no package reference for %s", pkg)
		}
		docs, err := fetchPackage(ctx, ref)
		if err != nil {
			return err
		}
		crds, err := selectCRDs(docs, names)
		if err != nil {
			return err
		}
		maps.Copy(selected, crds)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, name := range wanted {
		doc := selected[name]
		if !strings.HasSuffix(doc, "\n") {
			doc += "\n"
		}
		if err := os.WriteFile(filepath.Join(out, name+".yaml"), []byte(doc), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(out, "VERSION"), []byte(tag+"\n"), 0o644)
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func collectPackages(ctx context.Context, path string) (map[string]packageRef, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, "", err
	}
	var refs []packageRef
	collectStrings(value, &refs)
	if len(refs) == 0 {
		return nil, "", errors.New("no provider package references found")
	}
	tag := refs[0].tag
	for _, ref := range refs {
		if ref.tag != tag {
			return nil, "", fmt.Errorf("provider package tags differ: %s and %s", tag, ref.tag)
		}
	}
	packages := map[string]packageRef{}
	for _, ref := range refs {
		packages[strings.TrimPrefix(ref.repository, "upbound/")] = ref
	}
	return packages, tag, nil
}

func collectStrings(value any, refs *[]packageRef) {
	switch v := value.(type) {
	case string:
		if !strings.HasPrefix(v, packagePrefix) {
			return
		}
		parts := strings.SplitN(v, "/", 2)
		repoTag := parts[1]
		at := strings.LastIndex(repoTag, ":")
		if at < 0 {
			return
		}
		*refs = append(*refs, packageRef{registry: parts[0], repository: repoTag[:at], tag: repoTag[at+1:]})
	case map[string]any:
		for _, child := range v {
			collectStrings(child, refs)
		}
	case []any:
		for _, child := range v {
			collectStrings(child, refs)
		}
	}
}

func packageForCRD(name string) (string, error) {
	parts := strings.Split(name, ".")
	if len(parts) != 6 || parts[2] != "gcp" || parts[3] != "m" || parts[4] != "upbound" || parts[5] != "io" {
		return "", fmt.Errorf("CRD %q does not have a supported GCP group", name)
	}
	return "provider-gcp-" + parts[1], nil
}

func splitDocuments(data []byte) []string {
	var docs []string
	var current strings.Builder
	for line := range strings.SplitAfterSeq(string(data), "\n") {
		if strings.TrimSpace(line) == "---" {
			if strings.TrimSpace(current.String()) != "" {
				docs = append(docs, current.String())
			}
			current.Reset()
			continue
		}
		current.WriteString(line)
	}
	if strings.TrimSpace(current.String()) != "" {
		docs = append(docs, current.String())
	}
	return docs
}

func selectCRDs(docs []string, wanted []string) (map[string]string, error) {
	want := map[string]bool{}
	for _, name := range wanted {
		want[name] = true
	}
	found := map[string]string{}
	for _, doc := range docs {
		var obj struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			return nil, err
		}
		if obj.Kind != "CustomResourceDefinition" || !want[obj.Metadata.Name] {
			continue
		}
		if _, ok := found[obj.Metadata.Name]; ok {
			return nil, fmt.Errorf("CRD %s appears twice", obj.Metadata.Name)
		}
		found[obj.Metadata.Name] = doc
	}
	for _, name := range wanted {
		if _, ok := found[name]; !ok {
			return nil, fmt.Errorf("CRD %s missing from package", name)
		}
	}
	return found, nil
}

func fetchPackage(ctx context.Context, ref packageRef) (docs []string, err error) {
	token := ""
	m, token, err := fetchManifest(ctx, ref, ref.tag, token)
	if err != nil {
		return nil, err
	}
	if len(m.Manifests) > 0 {
		entry := m.Manifests[0]
		for _, candidate := range m.Manifests {
			if candidate.Platform.OS == "linux" && candidate.Platform.Architecture == "amd64" {
				entry = candidate
				break
			}
		}
		m, token, err = fetchManifest(ctx, ref, entry.Digest, token)
		if err != nil {
			return nil, err
		}
	}
	for _, layer := range m.Layers {
		data, nextToken, err := fetch(ctx, ref, "blobs/"+layer.Digest, token, "")
		if err != nil {
			return nil, err
		}
		token = nextToken
		if strings.Contains(layer.MediaType, "gzip") {
			var reader *gzip.Reader
			reader, err = gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			defer func() {
				if cerr := reader.Close(); cerr != nil {
					err = errors.Join(err, fmt.Errorf("close gzip reader: %w", cerr))
				}
			}()
			data, err = io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
		}
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			header, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if strings.TrimLeft(header.Name, "./") == "package.yaml" {
				content, err := io.ReadAll(tr)
				if err != nil {
					return nil, err
				}
				return splitDocuments(content), nil
			}
		}
	}
	return nil, fmt.Errorf("package %s has no package.yaml", ref.repository)
}

func fetchManifest(ctx context.Context, ref packageRef, refName, token string) (manifest, string, error) {
	data, nextToken, err := fetch(ctx, ref, "manifests/"+refName, token, "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json")
	if err != nil {
		return manifest{}, "", err
	}
	var parsed manifest
	if err := json.Unmarshal(data, &parsed); err != nil {
		return manifest{}, "", err
	}
	return parsed, nextToken, nil
}

func fetch(ctx context.Context, ref packageRef, suffix, token, accept string) (data []byte, nextToken string, err error) {
	endpoint := "https://" + ref.registry + "/v2/" + ref.repository + "/" + suffix
	request := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return registryClient.Do(req)
	}
	resp, err := request(token)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode == http.StatusUnauthorized && token == "" {
		challenge, err := unauthorizedChallenge(ctx, resp)
		if err != nil {
			return nil, "", err
		}
		token, err = bearerToken(ctx, challenge)
		if err != nil {
			return nil, "", err
		}
		resp, err = request(token)
		if err != nil {
			return nil, "", err
		}
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close response body: %w", cerr))
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s: %s", endpoint, resp.Status)
	}
	data, err = io.ReadAll(resp.Body)
	return data, token, err
}

func unauthorizedChallenge(ctx context.Context, resp *http.Response) (challenge string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close response body: %w", cerr))
		}
	}()
	return resp.Header.Get("WWW-Authenticate"), nil
}

func bearerToken(ctx context.Context, challenge string) (token string, err error) {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return "", fmt.Errorf("unsupported authentication challenge %q", challenge)
	}
	fields := map[string]string{}
	for part := range strings.SplitSeq(strings.TrimPrefix(challenge, "Bearer "), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			fields[key] = strings.Trim(value, "\"")
		}
	}
	realm := fields["realm"]
	if realm == "" {
		return "", errors.New("bearer challenge has no realm")
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("service", fields["service"])
	query.Set("scope", fields["scope"])
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := registryClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close response body: %w", cerr))
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("bearer token response has no token")
}
