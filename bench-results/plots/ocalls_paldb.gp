set term postscript color eps enhanced 18
set encoding utf8
set output "ocalls_paldb.eps"
load "styles.inc"

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

set origin MX+LX+0*(IX+SX)-0.05,MY+0*(IY+SY)+LY
set size 0.65,SY
set yrange [0:8000]
set logscale y 10
set title "{/: #-ocalls w/ PalDB}" font ",13" offset 0.5,-0.5
set ylabel "#-ocalls" font "Helvetica,15" offset 2.8,0
set xlabel "Num of Keys in DB" font "Helvetica,15" offset 2.0,0
set ytics font  "Helvetica, 12" offset 0.75, 0
set xtic font "Helvetica, 12" offset .25,0.1

#set xlabel "Num of Keys in DB" offset 0,0.1
set key vertical maxrows 1 samplen 3 width 2 spacing -1 font "Helvetica,15" center at graph 0.5,1.195
set datafile separator ','
set key spacing 0.75 font ",10"
#set xtics ("10k","20k","30k","40k","50k","60k","70k","80k","90k")

plot 'data/ocalls_paldb.csv' using 1:2:xtic(1) title 'Full' with lines ls 2002,\
     'data/ocalls_paldb.csv' using 1:3:xtic(1) title 'Part-Read' with lines ls 2003,\
     'data/ocalls_paldb.csv' using 1:4:xtic(1) title 'Part-Write' with lines ls 2005
     

#plot for [COL=2:3] 'data/paldb.csv' using COL:xticlabels(1) title columnheader 



!epstopdf "ocalls_paldb.eps"
!rm "ocalls_paldb.eps"
quit