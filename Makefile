.PHONY: test docker-test

test:
	go test ./... --race --coverprofile coverage.out

docker-test:
	$(eval WORKDIR := /go/src/github.com/everoute/template-repo)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) golang:1.19 make test
