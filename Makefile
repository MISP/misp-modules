# https://www.mkdocs.org/user-guide/deploying-your-docs/

.PHONY: prepare_docs generate_docs ci_generate_docs test_docs

prepare_docs:
	cd doc; python generate_documentation.py
	mkdir -p docs/expansion/logos docs/export_mod/logos docs/import_mod/logos
	cp -R doc/logos/* docs/expansion/logos
	cp -R doc/logos/* docs/export_mod/logos
	cp -R doc/logos/* docs/import_mod/logos
	cp LICENSE docs/license.md

install_requirements:
	pip install -r docs/REQUIREMENTS.txt

generate_docs: prepare_docs
	mkdocs build

deploy:
	mkdocs gh-deploy

test_docs: prepare_docs
	mkdocs serve


# DOCKER make commands
generate_docs_docker: prepare_docs
	docker run --rm -it -v $(PWD):/docs squidfunk/mkdocs-material build

deploy_docker:
	docker run --rm -it -v $(PWD):/docs -v /home/$(whoami)/.docker:/root/.docker:ro squidfunk/mkdocs-material gh-deploy

test_docs_docker: prepare_docs
	docker run --rm -it -p 8000:8000 -v $(PWD):/docs squidfunk/mkdocs-material
