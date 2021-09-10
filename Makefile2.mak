DEX_IMAGE ?= "quay.io/dexidp/dex:v2.28.1"

.PHONY: dex-image
dex-image:
	@echo ""
	@echo "Using DEX_IMAGE: $(DEX_IMAGE)"
	perl -pi -e "s#quay.io/dexidp/dex:v2.28.1#${DEX_IMAGE}#g" config/manager/manager.yaml


.PHONY: bits
bits: build dex-image manifests docker-build docker-push bundle bundle-build bundle-push


.PHONY: sdk-run
sdk-run:
	@echo ""
	@echo "Using VERSION: $(VERSION)"
	operator-sdk run bundle $(BUNDLE_IMG)

.PHONY: sample
sample:
	@echo ""
	@echo "Creating a DexConfig instance ..."
	oc apply -f ./config/samples/dexconfig.yaml


.PHONY: sample-gitops
sample-gitops:
	@echo ""
	@echo "Creating a DexConfig instance for gitops ..."
	oc apply -f ./config/samples/dexconfig-gitops.yaml


.PHONY: curl
curl:
	@echo ""
	@curl -k https://$(shell oc get route -l app=dex2 -ojsonpath='{.items[].spec.host}')/.well-known/openid-configuration
	@curl -k -I https://$(shell oc get route -l app=dex2 -ojsonpath='{.items[].spec.host}')/.well-known/openid-configuration
	@curl https://$(shell oc get route -l app=dex2 -ojsonpath='{.items[].spec.host}')/.well-known/openid-configuration
	@echo "Verify openid configuration"
	@echo "curl https://$(shell oc get route -l app=dex2 -ojsonpath='{.items[].spec.host}')/.well-known/openid-configuration"

.PHONY: cleanup
cleanup:
	operator-sdk cleanup dex-operator

.PHONY: wait
wait:
	sleep 20

.PHONY: proto
proto:
	protoc \
	--go_out=. \
	--go_opt=paths=source_relative \
	--go-grpc_out=. \
	--go-grpc_opt=paths=source_relative \
	pkg/api/api.proto

.PHONY: check
check:
	oc get secrets mtls-secret-mtls -ojsonpath='{.data.\ca\.crt}' | base64 --decode > ca.crt
	oc get secrets mtls-secret-mtls -ojsonpath='{.data.\client\.crt}' | base64 --decode > client.crt
	oc get secrets mtls-secret-mtls -ojsonpath='{.data.\tls\.crt}' | base64 --decode > tls.crt
	openssl verify -CAfile ca.crt tls.crt
	openssl verify -CAfile ca.crt client.crt
	rm ca.crt client.crt tls.crt

