package client

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetCACertificates(t *testing.T) {
	type testCase struct {
		name            string
		trustBundle     string
		caBundlePresent bool
		assertions      func(t *testing.T, certs []*x509.Certificate)
	}

	testCases := []testCase{
		{
			name:            "no trust bundle",
			caBundlePresent: false,
			assertions: func(t *testing.T, certs []*x509.Certificate) {
				assert.Nil(t, certs)
			},
		},
		{
			name:            "empty trust bundle",
			caBundlePresent: true,
			trustBundle:     "",
			assertions: func(t *testing.T, certs []*x509.Certificate) {
				assert.Nil(t, certs)
			},
		},
		{
			name:            "single certificate",
			caBundlePresent: true,
			trustBundle: `
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUWn739ioGaXBxeHg8FNAHHfag37IwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjA4MTgyMTM0MTRaFw0zMjA4
MTUyMTM0MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDhDQ1KESLi3DtHTQllnLZ7wasKgcz6bDF5QmI6hQL2
2CRLF1GWw8xg3qTTDPy0FwEYq+8dAdRqE6Lft/ZzpNtXyFa8iPZdH5egNqxS2rrd
xXKicu5ce4MDj/hmpDsfEKJKKOVl8u0vUUccmcsGaS6bqVrXJvenNbeYOXOKjuIG
Z8jDRx906G//uMsUn+ISfB91aFyHRvYfmRp1aQY1i5qxr0oCMUiG6VOBY9mvYZB+
CQbJVv0Tldmtpx0phGRZycIvAGHkxMvylyepZG3NaiYABJnV5ZtpXEmcHJnXrkeU
seLa1HQt9uyO9phw7jJl6uhmXmNIjSI7E2PacnknyDpnAgMBAAGjUzBRMB0GA1Ud
DgQWBBRcM9kTVIvbh3LriH71BhVQwU5EZDAfBgNVHSMEGDAWgBRcM9kTVIvbh3Lr
iH71BhVQwU5EZDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBa
pRUG9O9oPd2VorOEOiQa/kUHXT8i3zyljOv9TUGaWB7KvyJPy8V0UMCXQdLfuNp9
Jj8nhQpVN0LpDxq0jMkhWC21RdcCQ8uBpIZb87qvUNxBcHRnWHvVFFrb1l6d2TzT
EAdbMOOj8rWHhuq0rGZkhYz7hUUK873YZP9FMuhppiGcapDmfUJpR4956AYtkv8f
rvMLWhytaYxZJQrN2r8uNsklhQytJc9ZjfgGOmHkSvxUPkG6e4bts2leFVBK/g8m
NlyAQFLn7C06paTuNQkjtXypFT1ndHy4+hYewW+Yz9KvpmdmIZ4UqjEspX8vA3Lr
JvkUkvQfzDkQWnyL7D6D
-----END CERTIFICATE-----
`,
			assertions: func(t *testing.T, certs []*x509.Certificate) {
				assert.Len(t, certs, 1)
			},
		},
		{
			name:            "multiple certificates",
			caBundlePresent: true,
			trustBundle: `
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUWn739ioGaXBxeHg8FNAHHfag37IwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjA4MTgyMTM0MTRaFw0zMjA4
MTUyMTM0MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDhDQ1KESLi3DtHTQllnLZ7wasKgcz6bDF5QmI6hQL2
2CRLF1GWw8xg3qTTDPy0FwEYq+8dAdRqE6Lft/ZzpNtXyFa8iPZdH5egNqxS2rrd
xXKicu5ce4MDj/hmpDsfEKJKKOVl8u0vUUccmcsGaS6bqVrXJvenNbeYOXOKjuIG
Z8jDRx906G//uMsUn+ISfB91aFyHRvYfmRp1aQY1i5qxr0oCMUiG6VOBY9mvYZB+
CQbJVv0Tldmtpx0phGRZycIvAGHkxMvylyepZG3NaiYABJnV5ZtpXEmcHJnXrkeU
seLa1HQt9uyO9phw7jJl6uhmXmNIjSI7E2PacnknyDpnAgMBAAGjUzBRMB0GA1Ud
DgQWBBRcM9kTVIvbh3LriH71BhVQwU5EZDAfBgNVHSMEGDAWgBRcM9kTVIvbh3Lr
iH71BhVQwU5EZDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBa
pRUG9O9oPd2VorOEOiQa/kUHXT8i3zyljOv9TUGaWB7KvyJPy8V0UMCXQdLfuNp9
Jj8nhQpVN0LpDxq0jMkhWC21RdcCQ8uBpIZb87qvUNxBcHRnWHvVFFrb1l6d2TzT
EAdbMOOj8rWHhuq0rGZkhYz7hUUK873YZP9FMuhppiGcapDmfUJpR4956AYtkv8f
rvMLWhytaYxZJQrN2r8uNsklhQytJc9ZjfgGOmHkSvxUPkG6e4bts2leFVBK/g8m
NlyAQFLn7C06paTuNQkjtXypFT1ndHy4+hYewW+Yz9KvpmdmIZ4UqjEspX8vA3Lr
JvkUkvQfzDkQWnyL7D6D
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIUZOD4pznfHyCO8gMvP87F+PnhGHMwDQYJKoZIhvcNAQEL
BQAwNDELMAkGA1UEBhMCREUxFDASBgNVBAgMC0xhbmQgQmVybGluMQ8wDQYDVQQH
DAZCZXJsaW4wHhcNMjIwODI1MTYxNzI5WhcNMzIwODIyMTYxNzI5WjA0MQswCQYD
VQQGEwJERTEUMBIGA1UECAwLTGFuZCBCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO280znVj6qLpCqAeNgpw7gw
0OE54gBW8Y9gBtEYxBux6hXBl+doj+JNZLcfIoDoqdTlgZX13Y//WakfMuvuhYUN
53fpwsiup3pqqL+JHhKy+Bq/BSQcHkLGi/aUGph7qK/wQMZBGBbbBXaCwnhjYovl
nRq4p+Cm5wm4S/QUhgyvqyoeNWAc6+2AHniuIzo6Q1MU9ktaSAdL8ZdW5g6el5iA
oHjDHNjTwyTeybKFScEQvFqO6qfzTRn8eV6dwH4gOYec1IdDwSp8PSv9R7J9AC+1
DtAjsYtqO4i6qRpgf0zyGQb+uNKXdz/ovOGa58twfMKYU7Z2crPj3K7NOJVelZEC
AwEAAaN0MHIwHQYDVR0OBBYEFPlcZspynb+2DwRN5K3slRyEV0nxMB8GA1UdIwQY
MBaAFPlcZspynb+2DwRN5K3slRyEV0nxMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUB
Af8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBACXY
FH72svBSALkqmTyU9rsh4rRK9yo7tmNJkFkRQ/cjYycpNKZ6Cg9+wGwN6o6pXdqb
JfeuePclDdGcgYe8SbGr0T7pFXdUIVmuO/jjatKCftXQQZK5zHCkUTLhVlAbnNpC
3NIU4wWjx/QLtk+zEqjl5kyDgXD5GwxXbgzzY+7wi4QZO8VRyLG5lawZVKer3gkt
+NGIOtoyz4RjnWIKV34Z6HUDhdgbVyX1uPG/a5mLmcbLjuSf39WdAgv9bFGkUHZk
2dU0bIXepIZ5Mz3aovl35EjbGAbpI8tpKWlsHNoiVNQm1vojfKvKVibVS2FNo0cD
gu45O/O1hxzezDKiKKU=
-----END CERTIFICATE-----
`,
			assertions: func(t *testing.T, certs []*x509.Certificate) {
				assert.Len(t, certs, 2)
				assert.NotEqual(t, certs[0], certs[1])
			},
		},
		{
			name:            "multiple certificates with different content",
			caBundlePresent: true,
			trustBundle: `
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUWn739ioGaXBxeHg8FNAHHfag37IwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjA4MTgyMTM0MTRaFw0zMjA4
MTUyMTM0MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDhDQ1KESLi3DtHTQllnLZ7wasKgcz6bDF5QmI6hQL2
2CRLF1GWw8xg3qTTDPy0FwEYq+8dAdRqE6Lft/ZzpNtXyFa8iPZdH5egNqxS2rrd
xXKicu5ce4MDj/hmpDsfEKJKKOVl8u0vUUccmcsGaS6bqVrXJvenNbeYOXOKjuIG
Z8jDRx906G//uMsUn+ISfB91aFyHRvYfmRp1aQY1i5qxr0oCMUiG6VOBY9mvYZB+
CQbJVv0Tldmtpx0phGRZycIvAGHkxMvylyepZG3NaiYABJnV5ZtpXEmcHJnXrkeU
seLa1HQt9uyO9phw7jJl6uhmXmNIjSI7E2PacnknyDpnAgMBAAGjUzBRMB0GA1Ud
DgQWBBRcM9kTVIvbh3LriH71BhVQwU5EZDAfBgNVHSMEGDAWgBRcM9kTVIvbh3Lr
iH71BhVQwU5EZDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBa
pRUG9O9oPd2VorOEOiQa/kUHXT8i3zyljOv9TUGaWB7KvyJPy8V0UMCXQdLfuNp9
Jj8nhQpVN0LpDxq0jMkhWC21RdcCQ8uBpIZb87qvUNxBcHRnWHvVFFrb1l6d2TzT
EAdbMOOj8rWHhuq0rGZkhYz7hUUK873YZP9FMuhppiGcapDmfUJpR4956AYtkv8f
rvMLWhytaYxZJQrN2r8uNsklhQytJc9ZjfgGOmHkSvxUPkG6e4bts2leFVBK/g8m
NlyAQFLn7C06paTuNQkjtXypFT1ndHy4+hYewW+Yz9KvpmdmIZ4UqjEspX8vA3Lr
JvkUkvQfzDkQWnyL7D6D
-----END CERTIFICATE-----
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIUZOD4pznfHyCO8gMvP87F+PnhGHMwDQYJKoZIhvcNAQEL
BQAwNDELMAkGA1UEBhMCREUxFDASBgNVBAgMC0xhbmQgQmVybGluMQ8wDQYDVQQH
DAZCZXJsaW4wHhcNMjIwODI1MTYxNzI5WhcNMzIwODIyMTYxNzI5WjA0MQswCQYD
VQQGEwJERTEUMBIGA1UECAwLTGFuZCBCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO280znVj6qLpCqAeNgpw7gw
0OE54gBW8Y9gBtEYxBux6hXBl+doj+JNZLcfIoDoqdTlgZX13Y//WakfMuvuhYUN
53fpwsiup3pqqL+JHhKy+Bq/BSQcHkLGi/aUGph7qK/wQMZBGBbbBXaCwnhjYovl
nRq4p+Cm5wm4S/QUhgyvqyoeNWAc6+2AHniuIzo6Q1MU9ktaSAdL8ZdW5g6el5iA
oHjDHNjTwyTeybKFScEQvFqO6qfzTRn8eV6dwH4gOYec1IdDwSp8PSv9R7J9AC+1
DtAjsYtqO4i6qRpgf0zyGQb+uNKXdz/ovOGa58twfMKYU7Z2crPj3K7NOJVelZEC
AwEAAaN0MHIwHQYDVR0OBBYEFPlcZspynb+2DwRN5K3slRyEV0nxMB8GA1UdIwQY
MBaAFPlcZspynb+2DwRN5K3slRyEV0nxMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUB
Af8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBACXY
FH72svBSALkqmTyU9rsh4rRK9yo7tmNJkFkRQ/cjYycpNKZ6Cg9+wGwN6o6pXdqb
JfeuePclDdGcgYe8SbGr0T7pFXdUIVmuO/jjatKCftXQQZK5zHCkUTLhVlAbnNpC
3NIU4wWjx/QLtk+zEqjl5kyDgXD5GwxXbgzzY+7wi4QZO8VRyLG5lawZVKer3gkt
+NGIOtoyz4RjnWIKV34Z6HUDhdgbVyX1uPG/a5mLmcbLjuSf39WdAgv9bFGkUHZk
2dU0bIXepIZ5Mz3aovl35EjbGAbpI8tpKWlsHNoiVNQm1vojfKvKVibVS2FNo0cD
gu45O/O1hxzezDKiKKU=
-----END CERTIFICATE-----
`,
			assertions: func(t *testing.T, certs []*x509.Certificate) {
				assert.Len(t, certs, 2)
				assert.NotEqual(t, certs[0], certs[1])
			},
		},
	}

	for _, tc := range testCases {
		clientSet := fake.NewSimpleClientset()
		_, err := clientSet.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: userCAConfigMapNamespace,
			},
		}, metav1.CreateOptions{})
		assert.NoError(t, err)

		if tc.caBundlePresent {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: userCAConfigMap,
				},
				Data: map[string]string{
					userCABundleKey: tc.trustBundle,
				},
			}
			_, err = clientSet.CoreV1().ConfigMaps(userCAConfigMapNamespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			assert.NoError(t, err)
		}

		certs := getCACertificates(context.TODO(), clientSet)
		tc.assertions(t, certs)
	}
}
