NAME=manual

all: $(NAME).tex
	latex $(NAME).tex
	pdflatex $(NAME).tex
	bibtex $(NAME).aux
	latex $(NAME).tex
	latex $(NAME).tex
	latex $(NAME).tex
	dvips -t a4 $(NAME).dvi
	ps2pdf $(NAME).ps

clean:
	rm $(NAME).aux $(NAME).log $(NAME).pdf $(NAME).dvi $(NAME).ps $(NAME).bbl $(NAME).blg $(NAME).out
