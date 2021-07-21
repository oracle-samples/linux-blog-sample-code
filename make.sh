#! /bin/bash

set -e
set -u
set -x

pdflatex main
convert -density 150 main.pdf -quality 90 -background white -alpha remove -alpha off cheatsheet.png
