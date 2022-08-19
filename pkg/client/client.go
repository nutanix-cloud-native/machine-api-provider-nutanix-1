package client

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	nutanixClient "github.com/nutanix-cloud-native/prism-go-client"
	nutanixClientV3 "github.com/nutanix-cloud-native/prism-go-client/v3"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	ProviderName = "nutanix"

	// GlobalInfrastuctureName default name for infrastructure object
	GlobalInfrastuctureName = "cluster"

	// KubeCloudConfigNamespace is the namespace where the kube cloud config ConfigMap is located
	KubeCloudConfigNamespace = "openshift-config-managed"
	// kubeCloudConfigName is the name of the kube cloud config ConfigMap
	kubeCloudConfigName = "kube-cloud-config"
	// cloudCABundleKey is the key in the kube cloud config ConfigMap where the custom CA bundle is located
	cloudCABundleKey         = "ca-bundle.pem"
	userCAConfigMapNamespace = "openshift-config"
	userCAConfigMap          = "user-ca-bundle"
	userCABundleKey          = "ca-bundle.crt"

	// Nutanix credential keys
	NutanixEndpointKey = "NUTANIX_PRISM_CENTRAL_ENDPOINT"
	NutanixPortKey     = "NUTANIX_PRISM_CENTRAL_PORT"
	NutanixUserKey     = "NUTANIX_PRISM_CENTRAL_USER"
	NutanixPasswordKey = "NUTANIX_PRISM_CENTRAL_PASSWORD"
)

type ClientOptions struct {
	Credentials *nutanixClient.Credentials
	Debug       bool

	kubeClient kubernetes.Interface
}

func Client(options *ClientOptions) (*nutanixClientV3.Client, error) {
	if options.Credentials == nil {
		username := getEnvVar(NutanixUserKey)
		password := getEnvVar(NutanixPasswordKey)
		port := getEnvVar(NutanixPortKey)
		endpoint := getEnvVar(NutanixEndpointKey)
		options.Credentials = &nutanixClient.Credentials{
			Username: username,
			Password: password,
			Port:     port,
			Endpoint: endpoint,
		}
	}

	if len(options.Credentials.URL) == 0 {
		options.Credentials.URL = fmt.Sprintf("%s:%s", options.Credentials.Endpoint, options.Credentials.Port)
	}

	zapLog, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	if options.Debug {
		zapLog, err = zap.NewDevelopment()
		if err != nil {
			return nil, err
		}
	}
	logger := zapr.NewLogger(zapLog)

	clientOpts := []nutanixClientV3.ClientOption{
		nutanixClientV3.WithLogger(&logger),
	}
	ctx := logr.NewContext(context.Background(), logger)
	if certs := getCACertificates(ctx, options.kubeClient); certs != nil {
		logger.V(1).Info("Using custom CA certificate")
		for _, cert := range certs {
			clientOpts = append(clientOpts, nutanixClientV3.WithCertificate(cert))
		}
	}

	logger.V(1).Info("Creating new v3 client", "endpoint", options.Credentials.URL)
	cli, err := nutanixClientV3.NewV3Client(*options.Credentials, clientOpts...)
	if err != nil {
		logger.Error(err, "failed to create the nutanix v3 client")
		return nil, err
	}

	return cli, nil
}

func getEnvVar(key string) (val string) {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return
}

// getCACertificate gets the CA certificates from the user-ca-bundle configmap
func getCACertificates(ctx context.Context, kubeClient kubernetes.Interface) []*x509.Certificate {
	logger := logr.FromContextOrDiscard(ctx)
	configMap, err := kubeClient.CoreV1().ConfigMaps(userCAConfigMapNamespace).Get(ctx, userCAConfigMap, metav1.GetOptions{})
	if err != nil {
		logger.Info("failed to get user-ca-bundle configmap", "error", err)
		return nil
	}

	cacert, ok := configMap.Data[userCABundleKey]
	if !ok {
		logger.Info("failed to get cloud CA bundle from configmap")
		return nil
	}

	pemBlocks := []byte(cacert)
	certs := make([]*x509.Certificate, 0)
	for {
		block, rest := pem.Decode(pemBlocks)
		if block == nil {
			break
		}
		pemBlocks = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error(err, "failed to parse certificate", "certificate", block.Bytes)
			break
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		logger.Info("failed to parse any certificates from user-ca-bundle")
		return nil
	}

	return certs
}
