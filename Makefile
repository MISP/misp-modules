
.PHONY: prepare_docs generate_docs ci_generate_docs test_docs

prepare_docs:
	cd doc; python generate_documentation.py
	mkdir -p docs/expansion/logos docs/export_mod/logos docs/import_mod/logos
	cp -R doc/logos/* docs/expansion/logos
	cp -R doc/logos/* docs/export_mod/logos
	cp -R doc/logos/* docs/import_mod/logos
	cp LICENSE docs/license.md

generate_docs: prepare_docs
	docker run --rm -it -v $(PWD):/docs squidfunk/mkdocs-material build

ci_generate_docs: prepare_docs
	mkdocs gh-deploy

test_docs: prepare_docs
	docker run --rm -it -p 8000:8000 -v $(PWD):/docs squidfunk/mkdocs-material