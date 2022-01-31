srpm:
	dnf -y install git rpm-build gcc autoconf doxygen python3-lxml python3-cheetah python3-sphinx texlive-fncychap texlive-wrapfig texlive-capt-of texlive-framed texlive-upquote texlive-needspace texlive-tabulary texlive-cmap texlive-metafont texlive-ec texlive-babel-english texlive-tex-gyre texlive-parskip
	./.copr/make_srpm.sh --output $(outdir)
