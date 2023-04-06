set term postscript color eps enhanced 22
set encoding utf8
load "../styles.inc"
set output "scimark.eps"
set datafile separator ","
f(x)=1000000

NX=2
NY=2
# Size of graphs
SX=0.9
SY=0.8

# Margins
MX=0.075
MY=0.0
# Space between graphs
IX=-0.475
IY=-0.2
# Space for legends
LX=0.05
LY=0.01

set size 1.0,1.35

set lmargin MX+1
set rmargin MX+12

set tmargin MY+5.56
set bmargin MY+0.5

set multiplot

set ytics nomirror
set grid y


set style data histogram
set style histogram #clustered gap 10
set style fill solid border -1
set boxwidth 1 relative 
set bmargin 3
#set xrange [-1.25:4.5]
set yrange [0:1800]
set grid

# Small workload
set origin MX+LX+0*(IX+SX)-0.05,MY+1*(IY+SY)+LY
set size 0.65,SY

set title "{/: Small (cache contained)}" font ",15" offset 0,-0.75 #font ",15"
#set logscale y 10
set ytics font  "Helvetica, 12" offset 0.75, 0
set ylabel "Throughout (MFLOPS)" font ",15" offset 4
set xlabel "" font ",15"
set key vertical maxrows 1 samplen 1 width -1  font "Helvetica,18" center at graph 1.0,1.2

set xtic font "Helvetica, 12"offset .25,0.1

set xlabel offset 0,1
#set offset -0.75,-0.75,0,0
plot for [COL=2:3] 'data/small.csv' using COL:xticlabels(1) title columnheader 
#plot 'data/randread.csv' using 2:xtic(1) title "SSD (Ext4)" linecolor rgb "#006400" with boxes, \
#'' using 3:xtic(1) title "PM (Ext4-DAX)" linecolor rgb "#8B008B" with boxes, \
#'' using 4:xtic(1) title "Ramdisk (Tmpfs)" linecolor rgb "#FF0000" with boxes


# Medium size workload
set origin MX+LX+1*(IX+SX)-0.01,MY+1*(IY+SY)+LY
unset key
set title "{/: Medium}" font ",15"
unset ylabel
#set yrange [0:100]
plot for [COL=2:3] 'data/medium.csv' using COL:xticlabels(1) title columnheader 
#plot 'data/randread.csv' using 2:xtic(1) title "SSD (Ext4)" linecolor rgb "#006400" \
#'' using 3:xtic(1) title "PM (Ext4-DAX)" linecolor rgb "#8B008B" \
#'' using 4:xtic(1) title "Ramdisk (Tmpfs)" linecolor rgb "#FF0000" 

# Large workload
set origin MX+LX+0*(IX+SX)-0.05,MY+0*(IY+SY)+LY
set title "{/: Large (out-of-cache)}" font ",15"
set ylabel "Throughout (MFLOPS)" font ",15" offset 4
plot for [COL=2:3] 'data/large.csv' using COL:xticlabels(1) title columnheader 
#plot 'data/randread.csv' using 2:xtic(1) title "SSD (Ext4)" linecolor rgb "#006400" with boxes, \
#'' using 3:xtic(1) title "PM (Ext4-DAX)" linecolor rgb "#8B008B" with boxes, \
#'' using 4:xtic(1) title "Ramdisk (Tmpfs)" linecolor rgb "#FF0000" with boxes


!epstopdf "scimark.eps"
!rm "scimark.eps"
quit 