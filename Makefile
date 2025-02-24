# See: https://www.mkdocs.org/user-guide/deploying-your-docs/
# Running 'make' uses poetry-installed mkdocs
# Running 'USE_DOCKER=true make' uses docker mkdocs

.PHONY: prepare_docs generate_docs deploy test_docs

MKDOCS_DOCKER_IMAGE := squidfunk/mkdocs-material

DOCS_DIST_DIR := ./docs

DOCS_SRC_DIR := ./documentation

USE_DOCKER ?=

.DEFAULT_GOAL := generate_docs


prepare_docs:
	@echo "Preparing documentation."
	poetry install --with docs --extras "unstable"
	poetry run python $(DOCS_SRC_DIR)/generate_documentation.py
	mkdir -p $(DOCS_DIST_DIR)/logos
	mkdir -p $(DOCS_DIST_DIR)/img
	mkdir -p $(DOCS_DIST_DIR)/expansion/logos
	mkdir -p $(DOCS_DIST_DIR)/export_mod/logos
	mkdir -p $(DOCS_DIST_DIR)/import_mod/logos
	cp -R $(DOCS_SRC_DIR)/logos/* $(DOCS_DIST_DIR)/logos
	cp -R $(DOCS_SRC_DIR)/img/* $(DOCS_DIST_DIR)/img
	cp -R $(DOCS_SRC_DIR)/logos/* $(DOCS_DIST_DIR)/expansion/logos
	cp -R $(DOCS_SRC_DIR)/logos/* $(DOCS_DIST_DIR)/export_mod/logos
	cp -R $(DOCS_SRC_DIR)/logos/* $(DOCS_DIST_DIR)/import_mod/logos
	cp $(DOCS_SRC_DIR)/mkdocs/*.md $(DOCS_DIST_DIR)
	cp LICENSE $(DOCS_DIST_DIR)/license.md


generate_docs: prepare_docs
ifeq ($(USE_DOCKER), true)
	@echo "Generating documentation using '$(MKDOCS_DOCKER_IMAGE)'."
	docker run --rm -it -v $(PWD):/docs $(MKDOCS_DOCKER_IMAGE) build
else
	@echo "Generating docunentation."
	poetry run mkdocs build
endif


deploy: generate_docs
ifeq ($(USE_DOCKER), true)
	@echo "Deploying documentation using '$(MKDOCS_DOCKER_IMAGE)'."
	docker run --rm -it -v $(PWD):/docs -v /home/$(whoami)/.docker:/root/.docker:ro $(MKDOCS_DOCKER_IMAGE) gh-deploy
else
	@echo "Deploying docunentation."
	poetry run mkdocs gh-deploy
endif


test_docs: prepare_docs
ifeq ($(USE_DOCKER), true)
	@echo "Serving documentation using '$(MKDOCS_DOCKER_IMAGE)'."
	docker run --rm -it -v $(PWD):/docs -p 8000:8000 $(MKDOCS_DOCKER_IMAGE)
else
	@echo "Serving docunentation."
	poetry run mkdocs serve
endif
