.PHONY: docker-build, docker-build-test-image, \
		docker-local-test, docker-test, setup

CONTAINER_NAME = szaydel/smbprobe

REV := $(shell git rev-parse --short HEAD)

docker-build:
	docker build \
		-t $(CONTAINER_NAME):latest \
		-t $(CONTAINER_NAME):$(REV) .

docker-build-test-image:
	docker build \
		-t $(CONTAINER_NAME):test \
		-t $(CONTAINER_NAME):sha-$(REV) .

docker-test:
	cd testing && bash probe-end-to-end-test.sh

docker-local-test: docker-build-test-image
	cd testing && bash probe-end-to-end-test.sh

setup:
	python3 -m venv venv && \
	. venv/bin/activate && \
	pip3 install --upgrade pip && \
	pip3 install -r requirements.txt -r requirements-dev.txt
