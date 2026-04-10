package client

import (
	"fmt"
	"os"
	"sync"

	"gitlab.alibaba-inc.com/trust-computing/credential-provider-go-sdk/core/credential_provider_factory"
)

// RoleCredential holds temporary credentials obtained via role assumption (STS).
type RoleCredential struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

// roleProvider wraps the credential-provider SDK to obtain and refresh STS credentials.
type roleProvider struct {
	roleArn  string
	initOnce sync.Once
	initErr  error
}

// newRoleProvider creates a roleProvider. regionID and appName are used to initialise the
// credential-provider SDK (called once). If they are empty, the env vars NACOS_REGION_ID
// and NACOS_APP_NAME are consulted.
func newRoleProvider(roleArn, regionID, appName string) (*roleProvider, error) {
	if roleArn == "" {
		return nil, fmt.Errorf("roleArn is required for role auth")
	}
	if regionID == "" {
		regionID = os.Getenv("NACOS_REGION_ID")
	}
	if appName == "" {
		appName = os.Getenv("NACOS_APP_NAME")
	}
	if regionID == "" || appName == "" {
		return nil, fmt.Errorf("regionID and appName are required for role auth (set via config or env NACOS_REGION_ID / NACOS_APP_NAME)")
	}

	// Global SDK initialisation (idempotent via sync.Once inside the SDK or here).
	if err := credential_provider_factory.InitEnvSimple(regionID, appName); err != nil {
		return nil, fmt.Errorf("credential provider init failed: %w", err)
	}

	return &roleProvider{roleArn: roleArn}, nil
}

// GetCredential obtains (or refreshes) temporary AK/SK/SecurityToken via the SDK.
func (rp *roleProvider) GetCredential() (*RoleCredential, error) {
	provider, err := credential_provider_factory.GetOpenSDKV2CredProvider(rp.roleArn)
	if err != nil {
		return nil, fmt.Errorf("get credential provider failed: %w", err)
	}
	cred, err := provider.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("get credential failed: %w", err)
	}
	return &RoleCredential{
		AccessKeyID:     cred.AccessKeyId,
		AccessKeySecret: cred.AccessKeySecret,
		SecurityToken:   cred.SecurityToken,
	}, nil
}
