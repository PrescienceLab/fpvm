dep/angr:
	mkdir -p $@
	git clone https://github.com/angr/angr.git $@
	git -C $@ checkout 25844567d18564095e2e1f1b4f74141f76e8101f
	git -C $@ am --reject --whitespace=fix $(PWD)/patch/angr.patch 
	cp -r dep/angr/angr src/
	conda env create -f environment.yml
	conda activate fpvm_static_analysis_env


dep/e9patch:
	mkdir -p $@
	git clone https://github.com/GJDuck/e9patch.git $@
	cd $@ && ./build.sh


deps: dep/angr dep/e9patch
