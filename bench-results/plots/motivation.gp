set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "motivation.eps"
set datafile separator ","


#set key invert reverse Left outside
set key autotitle columnheader

yoffset=3

#set multiplot layout 1,2 title "Server B: real PM + sim SGX" font ",15" \
              #margins 0.1,0.95,0.1,0.7
set multiplot layout 1,2 \
              margins 0.1,0.95,0.1,0.65


set size 0.5,0.5
#set title "" font ",15"

set ytics font ",14"
set ylabel "Runtime (s)" font ",15" offset yoffset
set xrange [0:100]

set xlabel "% untrusted classes" font ",15"
set xtics("1" 1, "10" 10, "20" 20, "30" 30, "40" 40, "50" 50, "60" 60, "70" 70, "80" 80, "90" 90, "100" 100) font ",14"
set style fill solid border -1

set key box
set key spacing 1 font ",15"
set key invert reverse Left outside
set key ins vert
#set key left top

set grid
set boxwidth 0.2 relative

#bottom margin (between x tics and bottom page)
set bmargin 2

set xtics offset .25,0.5,0
set xlabel offset 0,1,0
#set xtics rotate by 90 right
#set xtics center

#set label 1 "No SGX" font ",10" at 0.8,0.45 rotate by 90 left

dx=0.2
offset=0

#------------------------------------------Plots-------------------------------------------------
set title "Computation intensive (CI) ops" font ",15"
# LHS plot: 
set yrange [6:10]
plot 'data/motivation/simFFT2.csv' using (100-$1):2 title 'CI' with lines ls 2003
     

unset ylabel
# RHS plot: 
set ytics offset 0.5

set title "I/O intensive ops" font ",15"
set yrange [0.015:0.08]
plot 'data/motivation/simIO.csv' using (100-$1):2 title 'I/O' with lines ls 2005 
#---------------------------------------------------------------------------------------------------



!epstopdf "motivation.eps"
!rm "motivation.eps"
quit