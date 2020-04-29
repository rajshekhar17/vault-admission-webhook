package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	av1 "k8s.io/api/admission/v1"
	"strconv"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	uv1 "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"github.com/hashicorp/vault/api"
	"os"
	"bytes"
	yamlv2 "gopkg.in/yaml.v2"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
	token = os.Getenv("TOKEN")
	role = os.Getenv("ROLE")
	vault_addr = os.Getenv("VAULT_ADDR")
	insecure, _ = strconv.ParseBool(os.Getenv("VAULT_SKIP_VERIFY"))
	vaultConfigPath = os.Getenv("VAULT_CONFIG_PATH")
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey = "vault-manifest/inject"
	admissionWebhookAnnotationStatusKey = "vault-manifest/status"
	admissionWebhookAnnotationPrefixKey = "vault-manifest-inject-secret"
)

type VaultConfig struct {
	Address		string	`yaml:"address"`
	Token		string	`yaml:"token"`
	Insecure	bool	`yaml:"insecure"`
}

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

type Config struct {
	Containers []corev1.Container `yaml:"containers"`
	Volumes    []corev1.Volume    `yaml:"volumes"`
}

type vaultTokenRequest struct {
	Role	string	`json:"role"`
	Jwt		string	`json:"jwt"`
}

type vaultTokenResponse struct {
	Auth struct {
		Token				string		`json:"client_token"`
		Accessor			string		`json:"accessor"`
		Policies			string		`json:"policies"`
		Metadata			interface{}	`json:"metadata"`
		Lease_duration		int64		`json:"lease_duration"`
		Renewable			bool		`json:"renewable"`

	} `json:"auth"`
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func getVaultSecret(client *api.Client, vaultPath string, key string) (string, error) {
	renewVaultTokenLease()
	secret, err := client.Logical().Read(vaultPath)
	if err != nil {
		glog.Errorf("Error fetching secret :%v",err)
		return "", err
	}
	if secret == nil {
		glog.Errorf("Error fetching secret from the specified path")
		return "", err
	}
	m, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", err
	}
	return m[key].(string), nil
}

func initVaultClient() (*api.Client, error){
	config := &api.Config{
		Address: vault_addr,
	}
	tlsConfig := &api.TLSConfig{
		Insecure: insecure,
	}
	config.ConfigureTLS(tlsConfig)
	client, err := api.NewClient(config)
	if err != nil {
		glog.Errorf("Error creating vault client : %v", err)
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

func getVaultConfig(){
	config := &VaultConfig{}
	if vaultConfigPath == "" {
		glog.Infof("No vaultconfig file defined using env vars")
	} else {
		// Open config file
		file, err := os.Open(vaultConfigPath)
		if err != nil {
			glog.Infof("Unable to locate vault config file, using env vars")
			return
		}
		defer file.Close()

		// Init new YAML decode
		d := yamlv2.NewDecoder(file)

		// Start YAML decoding from file
		if err := d.Decode(&config); err != nil {
			glog.Infof("Vault configuration file not valid")
			return
		} else {
			if config.Token != "" {
				token = config.Token//os.Getenv("TOKEN")
			}
			if config.Address != "" {
				vault_addr = config.Address//os.Getenv("VAULT_ADDR")
			}
			if config.Insecure == true {
				insecure = config.Insecure//os.Getenv("VAULT_SKIP_VERIFY")
			}
		}
	}
	if token == "" {
		glog.Infof("Unable to fetch token, trying kube auth method in vault")
		content, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			glog.Errorf("No service token assigned unable to continue")
			fmt.Errorf("%s",err)
		}

		// Convert []byte to string and print to screen
		kube_token := string(content)
		token, err = getVaultToken(kube_token)
		if err != nil {
			glog.Errorf("Unable to fetch vault token, this probably is not going to end well !!")
		}
	}
}

func init() {
	//_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	//_ = v1.AddToScheme(runtimeScheme)
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func getVaultToken(kube_token string) (string, error){
	url := fmt.Sprintf(vault_addr+"/v1/auth/kubernetes/login")
	requestPayload := &vaultTokenRequest{
		Role: role,
		Jwt:  kube_token,
	}
	j, err := json.Marshal(requestPayload)
	if err != nil {
		return "", err
	}
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(j))
    if err != nil {
		glog.Errorf("Unable to fetch token from vault using kubernetes auth and the service token...")
        return "", err
    }

    defer resp.Body.Close()
    bodyBytes, _ := ioutil.ReadAll(resp.Body)
	
    var reponseData vaultTokenResponse
	json.Unmarshal(bodyBytes, &reponseData)
	if strings.Contains(string(bodyBytes), "error:") {
		glog.Errorf("Error from vault: %s", string(bodyBytes))
	}
	if reponseData.Auth.Token != "" {
		glog.Infof("Fetched token using k8s auth")
	}
	return reponseData.Auth.Token, nil
}

func renewVaultTokenLease(){
	url := fmt.Sprintf(vault_addr+"/v1/auth/token/renew-self")
	
	client := &http.Client{}
	postData := []byte(`{}`)
	req, err := http.NewRequest("POST", url, bytes.NewReader(postData))
	req.Header.Add("X-Vault-Token", token)
	resp, err := client.Do(req)
	defer resp.Body.Close()
    if err != nil {
		glog.Errorf("Unable to renew vault token, further requests might fail..")
	}
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, kubeObj *uv1.Unstructured) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if kubeObj.GetNamespace() == namespace {
			glog.Infof("Skip mutation for %v for it's in special namespace:%v", kubeObj.GetName(), kubeObj.GetNamespace())
			return false
		}
	}

	annotations := kubeObj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
		default:
			required = false
		case "y", "yes", "true", "on":
			required = true
		}
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", kubeObj.GetNamespace(), kubeObj.GetName(), status, required)
	return required
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations/" + strings.Replace(key, "/","~1", -1),
				Value:  value,
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

func skipAnnotation(key string, value string) bool {
	if strings.Contains(key, admissionWebhookAnnotationPrefixKey) {
		if len(strings.Split(key, "/")) == 2 {
			if (strings.Split(key, "/")[0] != admissionWebhookAnnotationPrefixKey) {
				glog.Errorf("Annotation not specified correctly : %v", key)
				return true
			}
			if (len(strings.Split(strings.Split(key, "/")[1], ".")) < 2) {
				glog.Errorf("Annotation key should have atleast two level of manifest object reference")
				return true
			}
			if (len(strings.Split(value, ".")) == 2) {
				if (len(strings.Split(value, "/")) > 1) {
					return false
				} else {
					glog.Errorf("The Vault path should have atleast two level deep")
					return true
				}
			}
			glog.Errorf("Annotation didn't matched the filering criterion")
			return true
		} else {
			glog.Errorf("Annotation not specified correctly : %v", key)
			return true
		}
	} else {
		return true
	}
}

func patchVaultSecrets(annotations map[string]string) (patch []patchOperation){
	client, err := initVaultClient()
	if err != nil {
		glog.Errorf("Error creating vault client: %v", err)
		return []patchOperation{}
	}
	vaultPatch := []patchOperation{}
	for key, value := range annotations {
		if skipAnnotation(key, value) {
			continue
		}
		path := "/" + strings.Replace(strings.SplitAfterN(key, "/", 2)[1], ".", "/", -1)
		value, err := getVaultSecret(client, strings.Split(value, ".")[0], strings.SplitAfterN(value, ".", 2)[1])
		if err == nil {
			vaultPatch = append(vaultPatch, patchOperation{
				Op:		"add",
				Path:   path,
				Value:  value,
			})
		} else {
			glog.Errorf("Error processing annotation :%v", key)
		}
	}
	return vaultPatch
}

func createPatch(kubeObj *uv1.Unstructured, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation
	patch = append(patch, patchVaultSecrets(kubeObj.GetAnnotations())...)
	patch = append(patch, updateAnnotation(kubeObj.GetAnnotations(), annotations)...)
	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *av1.AdmissionReview) *av1.AdmissionResponse {
	getVaultConfig()
	req := ar.Request
	
	var kubeObj uv1.Unstructured
	r := strings.NewReplacer("\n", "")
	convertedBytes := []byte(r.Replace(string(req.Object.Raw)))
	
	if err := kubeObj.UnmarshalJSON(req.Object.Raw); err != nil {
		glog.Errorf("Error while unmarshal to unstructurd")
	}

	if _, _, err := deserializer.Decode(convertedBytes, nil, &kubeObj); err != nil {
		glog.Errorf("Can't decode body: %v", err)
	}
	
	glog.Infof("Annotations are: %v", kubeObj.GetAnnotations())
	
	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, kubeObj.GetName(), kubeObj.GetGenerateName(), req.UID, req.Operation, req.UserInfo)
	
	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &kubeObj) {
		glog.Infof("Skipping mutation for %s/%s%s due to policy check", kubeObj.GetNamespace(), kubeObj.GetName(), kubeObj.GetGenerateName())
		return &av1.AdmissionResponse{
			Allowed: true,
		}
	}

	// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
	//applyDefaultsWorkaround(whsvr.sidecarConfig.Containers, whsvr.sidecarConfig.Volumes)
	
	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&kubeObj, annotations)
	if err != nil {
		return &av1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &av1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *av1.PatchType {
			pt := av1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *av1.AdmissionResponse
	ar := av1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &av1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := av1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
