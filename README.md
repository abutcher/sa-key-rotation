# Service Account Signer Key Rotation

The OIDC issuer contains a `"keys.json"` key set which includes the public service Account signing key and information about the key such as the algorithm used to generate the key, etc. Third party integrations that want to verify the bound tokens issued by the service account signer will use the public keys defined in this key set file. Our replacement public key will need to be added to this key set file within our OIDC issuer so that third parties can verify bound tokens issued by the new private key.

```json
{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "TGXdmPbUYtPjvlM9tf8x3cgRuq_0-pMru22kh5fsyKI",
            "alg": "RS256",
            "n": "zDhEZsRkUVr3MZjVlbkg133H3vi5HKsLXiDkrJHcqoSc-bLH5-Rhpt2FkvYxqBKb_ND2SS-3yOvaUTcX3OE32vby79cp3eJlEcXedFRtWLsnh60YE146QP8t6eF4P4p8ewnDmHW2ojYpgbu8gQV7YJvVm5hUBSDJPTFALYD68yv8hhUj6IKMRS_au_wgXOH_A7c4Gh8gTZyrQp3UC-Y77g93qe86_03StS0feykgShUBftFSACkTaTFQIojLctTvvVMOQwFk__jChIHN3DfStwDKfcsiNMjkWRKg8r7gYE75hlZ9kRJ9oaZrSlZ3_1UA01SSGM3NPEG4LlhdOEhAEPOXpE2m037ByM-CVpIS-e5sGpVAi_7GBFGl6OMLBdLfpqEfYAXTjOtUwJe6pDaW1sifKlQPDuevvyJ1DSk-8KSJFnKmdzvRALKEWbJsjWEL6knTew0cpxmAVTWqysGLkd_DX0TcrD7ikDqFeDpCpwqdNcvAwXsExbqwZccMAgB24OJ9AF_8LrLKsgsIj4Cu4XjT-sCUNfANkKhkh-_9K4Tv8BLPJcYoj8xWZP9JvB-Ekjh4ywL_o7ht8bn7fk44kWm-jt_6C6EtXcT12F_3JpHiDwj8cgeiEqCxnMDGKLJS1ZAwqOt2HfCQO5d_4AGGTYQmmvAQA9gg5f2NWhiNwSc",
            "e": "AQAB"
        }
    ]
}
```

The active private Service Account signing key key is stored in the `bound-service-account-signing-key` secret within the `openshift-kube-apiserver` namespace. Modifications to this secret will be overwritten by the contents of the `next-bound-service-account-signing-key` secret in the `openshift-kube-apiserver-operator` namespace. The `bound-service-account-signing-key` secret should not be directly modified.

```yaml
apiVersion: v1
data:
  service-account.key: <base64 encoded RSA private key>
  service-account.pub: <base64 encoded RSA public key>
kind: Secret
metadata:
  name: bound-service-account-signing-key
  namespace: openshift-kube-apiserver
type: Opaque

```

**Note**: RSA key rotation can be achieved by deleting the `next-bound-service-account-signing-key` secret but this does not give us control over the keys we are replacing the existing keys with.

The active public key is stored within the `bound-sa-token-signing-certs` configmap within the `openshift-kube-apiserver` namespace. I suspect this configmap is the source for the public key exposed by the local OIDC which we override by setting a `serviceAccountIssuer` within the cluster's `authentication` object.

```yaml
apiVersion: v1
data:
  service-account-001.pub: |
    -----BEGIN RSA PUBLIC KEY-----
    <pubkey>
    -----END RSA PUBLIC KEY-----
kind: ConfigMap
metadata:
  name: bound-sa-token-signing-certs
  namespace: openshift-kube-apiserver
```

Background taken from [BZ1934363](https://bugzilla.redhat.com/show_bug.cgi?id=1934363):
"Any 3rd party integration that wants to verify bound tokens issued by a cluster needs to watch the configmap `openshift-config-managed/bound-sa-token-signing-certs`. This configmap contains the public keys needed to validate issued tokens. In the event of rotation the new public key will be added to the configmap and this key will be required to verify tokens issued by the new private key. Deploying a 3rd party integration statically with only a fixed set of public key(s) risks being unable to verify bound tokens issued after keypair rotation."

## Generate New RSA Key Pair

```sh
$ ccoctl aws create-key-pair --output-dir ./new
2023/02/16 14:46:30 Generating RSA keypair
2023/02/16 14:46:31 Writing private key to new/serviceaccount-signer.private
2023/02/16 14:46:31 Writing public key to new/serviceaccount-signer.public
2023/02/16 14:46:31 Copying signing key for use by installer
```

## Generate JSON Web Key Set keys.json File

```sh
$ go run jwks.go ./old/serviceaccount-signer.public ./new/serviceaccount-signer.public
2023/02/16 15:47:59 Reading public key
2023/02/16 15:47:59 Reading public key
```

The resultant key set will include a public key block for each public key provided.

```json
{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "TGXdmPbUYtPjvlM9tf8x3cgRuq_0-pMru22kh5fsyKI",
            "alg": "RS256",
            "n": "zDhEZsRkUVr3MZjVlbkg133H3vi5HKsLXiDkrJHcqoSc-bLH5-Rhpt2FkvYxqBKb_ND2SS-3yOvaUTcX3OE32vby79cp3eJlEcXedFRtWLsnh60YE146QP8t6eF4P4p8ewnDmHW2ojYpgbu8gQV7YJvVm5hUBSDJPTFALYD68yv8hhUj6IKMRS_au_wgXOH_A7c4Gh8gTZyrQp3UC-Y77g93qe86_03StS0feykgShUBftFSACkTaTFQIojLctTvvVMOQwFk__jChIHN3DfStwDKfcsiNMjkWRKg8r7gYE75hlZ9kRJ9oaZrSlZ3_1UA01SSGM3NPEG4LlhdOEhAEPOXpE2m037ByM-CVpIS-e5sGpVAi_7GBFGl6OMLBdLfpqEfYAXTjOtUwJe6pDaW1sifKlQPDuevvyJ1DSk-8KSJFnKmdzvRALKEWbJsjWEL6knTew0cpxmAVTWqysGLkd_DX0TcrD7ikDqFeDpCpwqdNcvAwXsExbqwZccMAgB24OJ9AF_8LrLKsgsIj4Cu4XjT-sCUNfANkKhkh-_9K4Tv8BLPJcYoj8xWZP9JvB-Ekjh4ywL_o7ht8bn7fk44kWm-jt_6C6EtXcT12F_3JpHiDwj8cgeiEqCxnMDGKLJS1ZAwqOt2HfCQO5d_4AGGTYQmmvAQA9gg5f2NWhiNwSc",
            "e": "AQAB"
        },
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "cuE9D_i7icDALhXFdpMATHno6bR1zk4LBSMaFZzPyhA",
            "alg": "RS256",
            "n": "w-fRDkWwRNnNAw18-0c55-Si_QRRKKZZgOW7HyzMRES4dlZSg_CqhIo_fv1JJiRj91GCjxlpwpgABfPtH4NgSlq_ol7pBXtNiJ3CWZLBACr73WM-r1nK2Mp3v_EHElxozDv1EavVp7ptSOn1xhgNECMJRj-2OhXfSb9FCtK7OC0IATDseFAgli5NOP3xwzD8-1YNRzIV023flWniFGmxykchVnTqJzIJMzzmqI9-gPZoaz5uy_WCgrGdfiRXEqq07RXm_pD5OGBoghnBl8ERTM3Um7CnLruxBUCPC9M1ddXbvemg54hC9mXXxPdmyKmWgeQXTo2unKvykC70qaT-8gJ4ry9gtM067TEfQwP-LGKC9tSdoRHpF5uphPuK2M2jo-DqiVwb1PxYd5SVj_T5fLn2yIBEXwRbPqq8DZTOg8ENl5nDWu99A8q_zfnUDwt10_zxaSB9OslwqVyPJvGUgvLJ6wj8dj0x6usahb1v0XE5ewekIZLLzoFA6CTkFJNqiWcH7Q_lCNLIvdtHXkyvvAEW36qOAlsvzIKf2asmvPUZygRlr5JiYzafdIjnw6B_YvbK1sC7fQVablnF0mUFnncO77nj-v7VqlQV2VBuuopoCdBNmmipSe8p_usUdofvNJx64y_NrSa9CY-lXTwXokQBR8nY_WKtZiPKu9NLXm8",
            "e": "AQAB"
        }
    ]
}
```

Replace the `keys.json` file within the OIDC with the newly generated key set that includes both the old and new public key.

## Modify `next-bound-service-account-signing-key` to Contain the New Key Pair

```sh
$ PRIVKEY=`base64 -w0 ./new/serviceaccount-signer.private`
$ PUBKEY=`base64 -w0 ./new/serviceaccount-signer.public`
$ oc patch secret next-bound-service-account-signing-key -n openshift-kube-apiserver-operator --type=json -p '[{"op":"replace","path":"/data/service-account.key","value":"'"$PRIVKEY"'"},{"op":"replace","path":"/data/service-account.pub","value":"'"$PUBKEY"'"}]'
```

Once we modify the `next-bound-service-account-signing-key` secret, the configmap containing the public key for local verification will be updated to include both the new and old public keys.

```sh
$ oc get configmap bound-sa-token-signing-certs -n openshift-kube-apiserver -o yaml
apiVersion: v1
data:
  service-account-001.pub: |
    -----BEGIN RSA PUBLIC KEY-----
    <pubkey>
    -----END RSA PUBLIC KEY-----
  service-account-002.pub: |
    -----BEGIN PUBLIC KEY-----
    <pubkey>
    -----END PUBLIC KEY-----
kind: ConfigMap
metadata:
  name: bound-sa-token-signing-certs
  namespace: openshift-kube-apiserver
```

API server pods will be automatically replaced.

```
$ oc get po -n openshift-kube-apiserver
kube-apiserver-ip-10-0-129-158.ec2.internal         5/5     Running     0          7m11s
kube-apiserver-ip-10-0-148-96.ec2.internal          5/5     Running     0          11m
kube-apiserver-ip-10-0-165-220.ec2.internal         5/5     Running     0          3m12s
```

The `bound-service-account-signing-key` secret in the `openshift-kube-apiserver` namespace will be automatically updated to contain the key we configured within the `next-bound-service-account-signing-key` secret.

Some time later...

Extract a token from a running pod and verify it against the new public key we generated previously to prove that the signing key has rotated.

```
$ oc rsync -n openshift-ingress-operator ingress-operator-55fdfbd748-mq4vk:/var/run/secrets/openshift/serviceaccount/..data/token /tmp/
$ go run validatejwt.go /tmp/token ./new/serviceaccount-signer.public
The token is valid
```