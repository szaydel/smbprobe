.PHONY: docker-build, docker-build-test-image, \
		docker-local-test, docker-test, lint, setup

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

lint:
	black *.py

setup:
	python3 -m venv venv && \
	. venv/bin/activate && \
	pip3 install --upgrade pip && \
	pip3 install -r requirements.txt -r requirements-dev.txt

unittest:
	python3 -m unittest -v test*py