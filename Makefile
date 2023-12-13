.PHONY: docker-build-release-images, docker-build-test-images, \
		docker-local-test, docker-test, lint, setup

PROBE_CNTR_NAME = szaydel/smbprobe
NOTIFIER_CNTR_NAME = szaydel/smbprobe-notifier

REV := $(shell git rev-parse --short HEAD)

docker-build-release-images:
	docker build -f Dockerfile.probe        \
		-t $(PROBE_CNTR_NAME):latest        \
		-t $(PROBE_CNTR_NAME):$(REV) .      \
	&&                                      \
	docker build -f Dockerfile.notifier     \
		-t $(NOTIFIER_CNTR_NAME):latest     \
		-t $(NOTIFIER_CNTR_NAME):$(REV) .

docker-build-test-images:
	docker build -f Dockerfile.probe        \
		-t $(PROBE_CNTR_NAME):latest        \
		-t $(PROBE_CNTR_NAME):test .        \
	&&                                      \
	docker build -f Dockerfile.notifier     \
		-t $(NOTIFIER_CNTR_NAME):latest     \
		-t $(NOTIFIER_CNTR_NAME):test .

docker-test:
	cd testing && bash probe-end-to-end-test.sh

docker-local-test: docker-build-test-image
	cd testing && bash probe-end-to-end-test.sh

format:
	black common/*.py notifier/*.py probe/*.py

lint: format
	ruff check probe/*py notifier/*py common/*py

setup:
	python3 -m venv venv && \
	. venv/bin/activate && \
	pip3 install --upgrade pip && \
	pip3 install -r requirements-dev.txt

unittest:
	python3 -m unittest -v notifier/test*.py probe/test*.py