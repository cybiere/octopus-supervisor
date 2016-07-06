rapport_octopus_cosnard_segretain.pdf : *.tex
	#pdflatex --shell-escape -jobname rapport_octopus_cosnard_segretain octopus-main 
	pdflatex --shell-escape -jobname rapport_octopus_cosnard_segretain octopus-main
	pdflatex --shell-escape -jobname rapport_octopus_cosnard_segretain octopus-main
	@echo "Fini, fichier rapport_octopus_cosnard_segretain.pdf"

clean :
	rm -f *.toc *.aux *.log *.out *.glo *.gls *.glg *.lof *.xdy

mrproper :
	rm -f *.toc *.aux *.log *.out *.glo *.gls *.glg *.lof *.xdy *.pdf *.pyg
