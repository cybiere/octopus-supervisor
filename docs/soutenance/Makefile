JOBNAME=soutenance_cnd_sgt

$(JOBNAME).pdf : *.tex
	pdflatex --shell-escape -jobname $(JOBNAME) main 
	pdflatex --shell-escape -jobname $(JOBNAME) main 
	@echo "Fini, fichier $(JOBNAME).pdf"

clean :
	rm -f *.toc *.aux *.log *.out *.glo *.gls *.glg *.lof *.xdy *.backup *.vrb *.nav *.snm

mrproper : clean
	rm -f *.pdf *.pyg
