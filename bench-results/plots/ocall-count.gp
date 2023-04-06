set term postscript color eps enhanced 18
set encoding utf8
load "styles.inc"
set output "ocall_count.eps"
set datafile separator ","

f(x)=1000000


NX=2
NY=1
# Size of graphs
SX=0.6
SY=0.6

# Margins
MX=0.075
MY=0.1
# Space between graphs
IX=-0.15
IY=0
# Space for legends
LX=0.05
LY=0.0

set size 0.6,0.6

set lmargin MX+1
set rmargin MX+12

set tmargin MY+5.56
set bmargin MY+0.5

set multiplot

set ytics nomirror
set grid 

set style data histogram
set style histogram #clustered gap 10
set style fill solid border -1


set origin MX+LX+0*(IX+SX)-0.05,MY+0*(IY+SY)+LY
set size 0.65,SY

set yrange [0:250]

#set logscale y 10

set title "{/: Most frequent ocalls}" font ",13" offset 0.5,-0.5
set ylabel "# Calls" font "Helvetica,15" offset 2.8,0
set xlabel "Ocall name" font "Helvetica,15" offset 2.0,0
set ytics font  "Helvetica, 13" offset 0.75, 0
set xtic font "Helvetica, 13" offset .25,0.1

#set xlabel "Num of Keys in DB" offset 0,0.1
set key vertical maxrows 1 samplen 3 width 2 spacing -1 font "Helvetica,18" center at graph 0.5,1.2
set datafile separator ','
set xtics rotate by 45 right


#set offset -0.75,-0.75,0,0
#plot for [COL=2:3] 'data/specjvm.csv' using COL:xticlabels(1) title columnheader 
plot 'data/ocall_count.csv' using 2:xtic(1) title "Ocall count"



!epstopdf "ocall_count.eps"
!rm "ocall_count.eps"
quit 