# Demo: Data Privacy and Application Security using Kuadrant

## Intro

Data Privacy and App Security are two major concerns related to system engineering and software applications often expressed by companies.

Data Privacy for global operations usually translates to multi-AZ/multi-region (multi-cluster architecture) at some point, and to the requirement of being more conscious about Personal Identifiable Information (PII) flying across regions overall. As for App Security, currently the top-1 concern is protecting/mitigating against Denial of Service (DoS) attacks.

To help tackle these issues, each of a set of solutions play an important part. Sometimes, the solutions for one problem overlap with another, allowing leveraging the economies of scale of applying one well thought-out software architecture that fits and solves for multiple problems at once.

This guide walks you through the steps of deploying an example system architecture, that is cloud-based, mainly composed of open source technologies, that combines a series of capabilities to address two main goals:

<table>
  <thead>
    <tr>
      <th>Goal</th>
      <th>Capability</th>
      <th>Reasoning</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2">
        Reduce client's PII exposure on E/W service communication across regions<br/>
        <sub><b>Track:</b> Data Privacy</sub>
      </td>
      <td>Geo</td>
      <td>Data isolation, compliance with regional regulations</td>
    </tr>
    <tr>
      <td>Token exchange</td>
      <td>For cross-cluster authentication – more limited scope and less-to-zero PII propagation</td>
    </tr>
    <tr>
      <td rowspan="8">
        Mitigate DoS risks<br/>
        <sub><b>Track:</b> App Security</sub>
      </td>
      <td>Flexible scaling</td>
      <td>Kubernetes superpower – first horizontally, sometimes vertically as well, if possible</td>
    </tr>
    <tr>
      <td>IP-RL</td>
      <td>First layer of protection</td>
    </tr>
    <tr>
      <td>Public Key Authentication methods</td>
      <td>E.g. OpenId Connect, mTLS – to avoid user/client ID exposure, avoid ID lookup bottleneck</td>
    </tr>
    <tr>
      <td>Efficient “offline” signature validation</td>
      <td>To avoid token lookup bottleneck</td>
    </tr>
    <tr>
      <td>Short-lived authentication tokens and/or support for immediate revocation</td>
      <td>To mitigate/remediate attacks that pass authentication; trade-offs between the two options to be considered</td>
    </tr>
    <tr>
      <td>Limited scope</td>
      <td>Isulation – to mitigate the impact of attacks that pass authentication</td>
    </tr>
    <tr>
      <td>Authenticated-RL</td>
      <td>Isulation – to mitigate the impact of attacks that pass authentication</td>
    </tr>
    <tr>
      <td>Geo</td>
      <td>Isulation – to mitigate the impact of attacks that pass authentication</td>
    </tr>
  </tbody>
</table>

### User story

The back story behind this use case is an enterprise that provides a simple HTTP service, and that now has to open a new cloud-based infrastructure at another region due to local data privacy regulations. Even though the service does not store personal data, the very association of HTTP requests to PII is considered a violation. Due to characteristics of how the service was designed as well as cost constraints, the company is not ready to run the main workload at all regions. Nevertheless, the company cannot give up on the users living across the globe where the regulations now impose more restrictive data privacy requirements.

Additionally, the company also wants to seize this opportunity of reviewing their cloud architecture to strengthen their measures to counter and mitigate against Denial of Service (DoS) threats, including the more specialized form Distributed Denial of Service (DDoS.)

### Stack

- [Kuadrant](https://kuadrant.io)
- [Keycloak](https://www.keycloak.org/) ⭐️
- [Istio](https://istio.io) ⭐️
- [cert-manager](https://cert-manager.io/) ⭐️
- [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io)
- [Skupper](https://skupper.io)
- [MetalLB](https://metallb.org/) ⭐️
- [AWS Route53](https://aws.amazon.com/route53)
- [Open Cluster Management](https://open-cluster-management.io/) ⭐️
- [Operator Lifecycle Manager](https://olm.operatorframework.io/) ⭐️
- [Kubernetes](https://kubernetes.io/) ⭐️

<sub>⭐️ CNCF projects</sub>

### Architecture

![Architecture](images/data-privacy-and-app-sec.jpg)

<br/>

High-level description of the components (manifest):
- 2 Kuberentes clusters – both connected through the cloud DNS service (AWS Route53) and distributing the incoming traffic directed to the workload service, according to the geolocation of the client:
  - **kind-mgc-control-plane**: control plane for the multi-cluster orchestration and host of the application service workload.
  - **kind-mgc-workload-1**: entrypoint cluster introduced to receive the traffic originated in the EU region, connected via E/W Skupper network to the main cluster that runs the service workload.

- 1 application service workload ("**echo**"): stateless single-instance application service that runs in the **kind-mgc-control-plane** cluster and can be consumed via HTTP at the `echo.MGC_ZONE_ROOT_DOMAIN` hostname from either region; requires E/W authentication tokens known as "Festival Wristbands" and it is rate-limited per user/client.

- 2 North-South (N/S) ingress gateways – managed by the multi-cluster orchestration and implemented in each cluster by Istio; listen to HTTP requests at the `*.MGC_ZONE_ROOT_DOMAIN` wildcard (exposed to the internet with support by MetalLB), with TLS enabled by attachment of a Kuadrant policy (certificates handled by cert-manager), as well as first-layer authentication enforced, with a configured token exchange step (for Festival Wristbands), before handing the traffic over to backend services; connected in the backend to the East-West (E/W) gateway via local route or Skupper network.

- 1 East-West (E/W) gateway – deployed to the **kind-mgc-control-plane** cluster, connected to the North-South (N/S) ingress gateways via local route and Skupper network, handles the traffic internally to the application service.

- Kuadrant Multi-Cluster Gateways ("**multi-cluster-gateways**"): handles the DNS policy and configuration with the cloud DNS service (AWS Route53), and leverages Open Cluster Management to orchestrate the propagation of ingress gateways and configuration across clusters.

- Kuadrant Service Protection ("**kuadrant-system**"): enforces the auth and rate-limit policies in the data plane, leveraging Authorino external authorization service and Limitador global rate-limiting service.

### Personas

3 personas (described below) will be represented in the tasks involved in deploying and consuming the system architecture described above.

- **👷🏾‍♀️ Platform Engineer**<br/>
  Responsible for creating the clusters and configuring the N/S and E/W gateways, as well as applying the 1st-layer security policies. In more complex scenarios, these responsibilities can be refined into the rather specialized roles of: Infrastructure Provider, Cluster Operator, Network Administrator, and Gateway Administrator.

- **🧑🏻‍💻 Application Developer**<br/>
  Responsible for building and deploying the application service, as well as connecting the service to gateways via specialized routes, and applying the policies that protect the service. In more complex scenarios, these responsibilities can be refined into the rather specialized roles of: Application Developer, and Policy Manager.

- **👩🏿‍💼 Client**<br/>
  Consumes the application service from either of the available regions, by authenticating with the authentication server first, then sending requests to the service via `curl`.

Other responsibilities abstracted in this guide include:
- Management of user/client identities in the Identity and Access Managament (IAM) system

Each group of tasks below is identified with the corresponding persona responsible for executing the tasks.

## Run the demo

### Requirements

Components you probably already have available in your local environment (minimum required versions indicated):
- [Docker](https://docker.io) (v24.0.6)
- [Kind](https://kind.sigs.k8s.io/) (v0.17.0)
- [kubectl](https://kubernetes.io/docs/reference/kubectl/) (v1.27.2)
- [curl](https://curl.se) (v8.1.2)
- [docker-mac-net-connect](https://github.com/chipmk/docker-mac-net-connect) (v0.1.2, macos only)
- [jq](https://stedolan.github.io/jq) (v1.6)

Make sure to prepare in advance as well:
- AWS account with a root domain and public Hosted Zone configured in Route53
- [Skupper CLI](https://skupper.io/start/index.html#step-1-install-the-skupper-commandline-tool-in-your-environment) (v1.4.3)

Certify your Docker environment is clean and with enough space to pull several container images.

<br/>

### ❶ Create the clusters ⋅ 👷🏾‍♀️ Platform Engineer

Export the shell variables that will be used across this demo:

```sh
export MGC_ZONE_ROOT_DOMAIN=example.net \
       MGC_AWS_DNS_PUBLIC_ZONE_ID= \
       MGC_AWS_ACCESS_KEY_ID= \
       MGC_AWS_SECRET_ACCESS_KEY= \
       MGC_AWS_REGION=eu-west-1 \
       MGC_BRANCH=release-0.1
```

Create the hub and spoke clusters, with the latest version of Kuadrant Multicluster Gateway Controller and Service Protection installed and ready to use in both clusters:

```sh
curl "https://raw.githubusercontent.com/kuadrant/multicluster-gateway-controller/${MGC_BRANCH}/hack/quickstart-setup.sh" | bash
```

The following Kubernetes clusters will be create and installed with Kuadrant:

| Cluster                    | Capacity         | Workload cluster | Ingress cluster  | Echo Service |
|----------------------------|:----------------:|:----------------:|:----------------:|:------------:|
| **kind-mgc-control-plane** | Multicluster Hub | Yes              | Yes (US traffic) | Yes          |
| **kind-mgc-workload-1**    | Spoke            | Yes              | Yes (EU traffic) | No           |

<br/>

### ❷ Connect the hub cluster ⋅ 👷🏾‍♀️ Platform Engineer

Create the base definition for your managed N/S ingress gateways:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: Gateway
metadata:
  name: north-south
  namespace: multi-cluster-gateways
  labels:
    cluster.open-cluster-management.io/placement: http-gateway
spec:
  gatewayClassName: kuadrant-multi-cluster-gateway-instance-per-cluster
  listeners:
  - name: api
    hostname: "*.$MGC_ZONE_ROOT_DOMAIN"
    port: 443
    protocol: HTTPS
    tls:
      mode: Terminate
      certificateRefs:
      - name: apps-hcpapps-tls
        kind: Secret
    allowedRoutes:
      namespaces:
        from: All
EOF
```

Enable TLS, by attaching a Kuadrant **TLSPolicy** to the N/S gateway definition:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: kuadrant.io/v1alpha1
kind: TLSPolicy
metadata:
  name: north-south
  namespace: multi-cluster-gateways
spec:
  targetRef:
    name: north-south
    group: gateway.networking.k8s.io
    kind: Gateway
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: glbc-ca
EOF
```

Configure your DNS service, by attaching a Kuadrant **DNSPolicy** to the N/S gateway definition:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: kuadrant.io/v1alpha1
kind: DNSPolicy
metadata:
  name: north-south
  namespace: multi-cluster-gateways
spec:
  targetRef:
    name: north-south
    group: gateway.networking.k8s.io
    kind: Gateway
  loadBalancing:
    geo:
      defaultGeo: US
EOF
```

<br/>

### ❸ Setup E/W plumbing ⋅ 👷🏾‍♀️ Platform Engineer

Create the E/W gateway:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: Gateway
metadata:
  name: east-west
  namespace: kuadrant-multi-cluster-gateways
  annotations:
    networking.istio.io/service-type: ClusterIP
spec:
  gatewayClassName: istio
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
EOF
```

Connect the E/W gateway to the N/S one:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: east-west
  namespace: kuadrant-multi-cluster-gateways
spec:
  parentRefs:
  - kind: Gateway
    name: north-south
    namespace: kuadrant-multi-cluster-gateways
  rules:
  - backendRefs:
    - name: east-west-istio
      port: 80
EOF
```

Give DNS a couple of minutes to update. You should then be able to execute the following and get back the correct A record:

```sh
dig echo.$MGC_ZONE_ROOT_DOMAIN
```

<br/>

### ❹ Setup authentication for N/S ⋅ 👷🏾‍♀️ Platform Engineer

Install Keycloak:

```sh
kubectl --context kind-mgc-control-plane create namespace keycloak
kubectl --context kind-mgc-control-plane apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml -n keycloak
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: keycloak
  namespace: keycloak
spec:
  parentRefs:
  - kind: Gateway
    name: north-south
    namespace: kuadrant-multi-cluster-gateways
  hostnames:
  - auth.$MGC_ZONE_ROOT_DOMAIN
  rules:
  - backendRefs:
    - name: keycloak
      port: 8080
---
apiVersion: kuadrant.io/v1beta2
kind: AuthPolicy
metadata:
  name: keycloak
  namespace: keycloak
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: keycloak
EOF
```

Create the AuthPolicy:

```sh
kubectl --context kind-mgc-control-plane apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: wristband-signing-key
  namespace: kuadrant-multi-cluster-gateways
stringData:
  key.pem: |
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIDHvuf81gVlWGo0hmXGTAnA/HVxGuH8vOc7/8jewcVvqoAoGCCqGSM49
    AwEHoUQDQgAETJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZxJKDysoGwn
    cnUvHIu23SgW+Ee9lxSmZGhO4eTdQeKxMA==
    -----END EC PRIVATE KEY-----
type: Opaque
---
apiVersion: kuadrant.io/v1beta2
kind: AuthPolicy
metadata:
  name: north-south
  namespace: kuadrant-multi-cluster-gateways
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: north-south
  rules:
    authentication:
      "keycloak-us":
        jwt:
          issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
    response:
      success:
        headers:
          authorization:
            wristband:
              issuer: http://authorino-authorino-oidc.kuadrant-system.svc.cluster.local:8083/kuadrant-multi-cluster-gateways/ap-kuadrant-multi-cluster-gateways-north-south/authorization
              customClaims:
                "scope":
                  selector: request.host
                "region":
                  value: us
              tokenDuration: 10
              signingKeyRefs:
              - name: wristband-signing-key
                algorithm: ES256
          append-prefix:
            key: authorization
            plain:
              selector: "Wristband {auth.response.authorization}"
            priority: 1
          host:
            plain:
              selector: |
                request.host.@replace:{"old":"$MGC_ZONE_ROOT_DOMAIN","new":"internal"}
EOF
```

<br/>

### ❺ Deploy the application ⋅ 🧑🏻‍💻 Application Developer

Deploy the application service onto the **kind-mgc-control-plane** cluster. The application attaches directly to the E/W gateway and indirectly to N/S:

```sh
kubectl create namespace echo
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - name: echo
        image: docker.io/jmalloc/echo-server
        ports:
        - name: http-port
          containerPort: 8080
          protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: echo
spec:
  ports:
  - name: http-port
    port: 8080
    targetPort: http-port
    protocol: TCP
  selector:
    app: echo
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: echo
  namespace: echo
spec:
  parentRefs:
  - kind: Gateway
    name: east-west
    namespace: kuadrant-multi-cluster-gateways
  hostnames:
  - echo.internal
  rules:
  - backendRefs:
    - name: echo
      port: 8080
EOF
```

Enforce authentication and authorization by attaching a Kuadrant **AuthPolicy** to the route:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: kuadrant.io/v1beta2
kind: AuthPolicy
metadata:
  name: echo
  namespace: echo
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: echo
  rules:
    authentication:
      "east-west":
        jwt:
          issuerUrl: http://authorino-authorino-oidc.kuadrant-system.svc.cluster.local:8083/kuadrant-multi-cluster-gateways/ap-kuadrant-multi-cluster-gateways-north-south/authorization
        credentials:
          authorizationHeader:
            prefix: Wristband
    authorization:
      scope:
        patternMatching:
          patterns:
          - selector: auth.identity.scope
            operator: eq
            value: "echo.$MGC_ZONE_ROOT_DOMAIN"
    response:
      success:
        dynamicMetadata:
          "userid":
            plain:
              selector: auth.identity.sub
EOF
```

Enforce rate-limit per user/client, by attaching a Kuadrant **RateLimitPolicy** to the route:

```sh
kubectl --context kind-mgc-control-plane apply -f - <<EOF
apiVersion: kuadrant.io/v1beta2
kind: RateLimitPolicy
metadata:
  name: echo
  namespace: echo
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: echo
  limits:
    "authenticated-per-user":
      rates:
      - limit: 5
        duration: 10
        unit: second
      counters:
      - metadata.filter_metadata.envoy\.filters\.http\.ext_authz.userid
EOF
```

Test the application protected by Kuadrant without an access token:

```sh
curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN -i
# HTTP/2 401
# www-authenticate: Bearer realm="keycloak-us"
# x-ext-auth-reason: credential not found
```

Test the 2-layer authentication by sending another request to the application with a valid Kubernetes authentication token:

```sh
export ACCESS_TOKEN=$(curl -k https://auth.$MGC_ZONE_ROOT_DOMAIN/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' -d 'scope=openid' | jq -r .access_token); echo $ACCESS_TOKEN
```

```sh
curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN -H "Authorization: Bearer $ACCESS_TOKEN" -i
# HTTP/2 200
#
# […]
# Host: echo.internal
# Accept: */*
# Authorization: Wristband […]
```

Inspect the tokens:

```sh
echo "-- N/S --"; jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$ACCESS_TOKEN"
echo "-- E/W --"; jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$(curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN -H "Authorization: Bearer $ACCESS_TOKEN" -i -s | grep Wristband | awk '{print $3}')"
```

<br/>

### ❻ Connect the spoke cluster ⋅ 👷🏾‍♀️ Platform Engineer

Introduce the **kind-mgc-workload-1** cluster as a second ingress cluster:

```sh
kubectl --context kind-mgc-control-plane label managedcluster kind-mgc-workload-1 ingress-cluster=true
kubectl --context kind-mgc-control-plane patch placement http-gateway -n multi-cluster-gateways --type='json' -p='[{"op": "replace", "path": "/spec/numberOfClusters", "value": 2}]'
kubectl --context kind-mgc-control-plane label --overwrite managedcluster kind-mgc-control-plane kuadrant.io/lb-attribute-geo-code=US
kubectl --context kind-mgc-control-plane label --overwrite managedcluster kind-mgc-workload-1 kuadrant.io/lb-attribute-geo-code=EU
```

Create the multi-cluster E/W plumbing:

```sh
skupper --context kind-mgc-control-plane --namespace kuadrant-multi-cluster-gateways init
skupper --context kind-mgc-control-plane --namespace kuadrant-multi-cluster-gateways token create /tmp/mgc-control-plane.token
skupper --context kind-mgc-control-plane --namespace kuadrant-multi-cluster-gateways service create east-west-skupper 80
skupper --context kind-mgc-control-plane --namespace kuadrant-multi-cluster-gateways service bind east-west-skupper service east-west-istio
skupper --context kind-mgc-workload-1 --namespace kuadrant-multi-cluster-gateways init
skupper --context kind-mgc-workload-1 --namespace kuadrant-multi-cluster-gateways link create /tmp/mgc-control-plane.token
```

Attach a HTTPRoute to the N/S gateway, pointing to the `east-west-istio` service in the **kind-mgc-control-plane** cluster (via Skupper proxy):

```sh
kubectl --context kind-mgc-workload-1 apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: east-west
  namespace: kuadrant-multi-cluster-gateways
spec:
  parentRefs:
  - kind: Gateway
    name: north-south
    namespace: kuadrant-multi-cluster-gateways
  rules:
  - backendRefs:
    - name: east-west-skupper
      port: 80
EOF
```

Give DNS a couple of minutes to update. You should then be able to execute the following and get back the correct A record:

```sh
dig echo.$MGC_ZONE_ROOT_DOMAIN
```

Install Keycloak in the **kind-mgc-workload-1** cluster:

```sh
kubectl --context kind-mgc-workload-1 create namespace keycloak
kubectl --context kind-mgc-workload-1 apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml -n keycloak
kubectl --context kind-mgc-workload-1 apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: keycloak
  namespace: keycloak
spec:
  parentRefs:
  - kind: Gateway
    name: north-south
    namespace: kuadrant-multi-cluster-gateways
  hostnames:
  - auth.$MGC_ZONE_ROOT_DOMAIN
  rules:
  - backendRefs:
    - name: keycloak
      port: 8080
---
apiVersion: kuadrant.io/v1beta2
kind: AuthPolicy
metadata:
  name: keycloak
  namespace: keycloak
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: keycloak
EOF
```

Setup N/S authentication in the **kind-mgc-workload-1** cluster:

```sh
kubectl --context kind-mgc-workload-1 apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: wristband-signing-key
  namespace: kuadrant-multi-cluster-gateways
stringData:
  key.pem: |
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIDHvuf81gVlWGo0hmXGTAnA/HVxGuH8vOc7/8jewcVvqoAoGCCqGSM49
    AwEHoUQDQgAETJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZxJKDysoGwn
    cnUvHIu23SgW+Ee9lxSmZGhO4eTdQeKxMA==
    -----END EC PRIVATE KEY-----
type: Opaque
---
apiVersion: kuadrant.io/v1beta2
kind: AuthPolicy
metadata:
  name: north-south
  namespace: kuadrant-multi-cluster-gateways
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: north-south
  rules:
    authentication:
      "keycloak-eu":
        jwt:
          issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
    response:
      success:
        headers:
          authorization:
            wristband:
              issuer: http://authorino-authorino-oidc.kuadrant-system.svc.cluster.local:8083/kuadrant-multi-cluster-gateways/ap-kuadrant-multi-cluster-gateways-north-south/authorization
              customClaims:
                "scope":
                  selector: request.host
                "region":
                  value: eu
              tokenDuration: 10
              signingKeyRefs:
              - name: wristband-signing-key
                algorithm: ES256
          append-prefix:
            key: authorization
            plain:
              selector: "Wristband {auth.response.authorization}"
            priority: 1
          host:
            plain:
              selector: |
                request.host.@replace:{"old":"$MGC_ZONE_ROOT_DOMAIN","new":"internal"}
EOF
```

<br/>

### ❼ Consume the service | 👩🏿‍💼 Client

#### From the default (US) region

```sh
export ACCESS_TOKEN=$(curl -k https://auth.$MGC_ZONE_ROOT_DOMAIN/realms/kuadrant/protocol/openid-connect/token --resolve auth.$MGC_ZONE_ROOT_DOMAIN:443:172.31.200.0 -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' -d 'scope=openid' | jq -r .access_token); echo $ACCESS_TOKEN
```

```sh
curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN --resolve echo.$MGC_ZONE_ROOT_DOMAIN:443:172.31.200.0 -H "Authorization: Bearer $ACCESS_TOKEN" -i
```

Inspect the tokens:

```sh
echo "-- N/S --"; jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$ACCESS_TOKEN"
echo "-- E/W --"; jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$(curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN --resolve echo.$MGC_ZONE_ROOT_DOMAIN:443:172.31.200.0 -H "Authorization: Bearer $ACCESS_TOKEN" -i -s | grep Wristband | awk '{print $3}')"
```

#### From the EU region

```sh
export ACCESS_TOKEN=$(curl -k https://auth.$MGC_ZONE_ROOT_DOMAIN/realms/kuadrant/protocol/openid-connect/token --resolve auth.$MGC_ZONE_ROOT_DOMAIN:443:172.31.201.0 -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' -d 'scope=openid' | jq -r .access_token); echo $ACCESS_TOKEN
```

```sh
curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN --resolve echo.$MGC_ZONE_ROOT_DOMAIN:443:172.31.201.0 -H "Authorization: Bearer $ACCESS_TOKEN" -i
```

Inspect the tokens:

```sh
echo "-- N/S --"; jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$ACCESS_TOKEN"
echo "-- E/W --"; jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$(curl -k https://echo.$MGC_ZONE_ROOT_DOMAIN --resolve echo.$MGC_ZONE_ROOT_DOMAIN:443:172.31.201.0 -H "Authorization: Bearer $ACCESS_TOKEN" -i -s | grep Wristband | awk '{print $3}')"
```

<br/>

## Cleanup

```sh
kind delete cluster --name mgc-control-plane
kind delete cluster --name mgc-workload-1
```
