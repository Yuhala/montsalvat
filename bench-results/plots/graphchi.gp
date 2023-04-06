set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "graphchi.eps"
set datafile separator ","


#set key invert reverse Left outside
set key autotitle columnheader

yoffset=3

#set multiplot layout 1,2 title "Server B: real PM + sim SGX" font ",15" \
              #margins 0.1,0.95,0.1,0.7
set multiplot layout 1,3 \
              margins 0.1,0.95,0.1,0.7

#set multiplot
#set style histogram clustered 
set style histogram rowstacked
#set style data histogram

set size 0.5,0.5
set title "" font ",15"
set yrange [0:2.5] 
set ytics font ",14"
set ylabel "Latency (s)" font ",15" offset yoffset
set xrange [0:7]
#set label 1 "Model Size (MB)" at screen 0.32,0.03 font ",15"
set xlabel "# of shards" font ",15"
set xtics("1" 1, "2" 2, "3" 3, "4" 4, "5" 5, "6" 6) font ",14"
set style fill solid border -1

set key box
set key spacing 1 font ",10"
set key invert reverse Left outside
set key ins vert
set key left top

set grid
set boxwidth 0.2 relative

#bottom margin (between x tics and bottom page)
set bmargin 2

set xtics offset .25,0.5,0
set xlabel offset 0,1,0
#set xtics rotate by 90 right
#set xtics center

#set label 1 "No SGX" font ",10" at 0.8,0.45 rotate by 90 left


#----------------------------Arrows-------------------------------
set arrow 1 from  0.8,1.7 to 0.8,0.1 lw 0 front size .3,10
set arrow 2 from  1,1.4 to 1,0.4 lw 0 front size .3,10
set arrow 3 from  1.2,1.2 to 1.2,0.28 lw 0 front size .3,10
#-----------------------------------------------------------------

#-------------------------- Labels--------------------------------
set label 1 "No SGX" font ",11" at 0.85,1.7
set label 2 "Full app in enclave" font ",11" at 1,1.4
set label 3 "Partitioned app" font ",11" at 1.2,1.25 
#-----------------------------------------------------------------




dx=0.2
offset=0

#------------------------------------------Plots-------------------------------------------------
set title "6.25k-V, 25k-E" font ",15"
# LHS plot: 
plot 'data/chi25k/chi-nosgx.csv' using ($1-dx):($2+$3) title "engine" linecolor rgb "#00643C" with boxes, \
'' using ($1-dx):3 title "sharding" linecolor rgb "#FFC300"  with boxes, \
'data/chi25k/chi-full.csv' using ($1+0):($2+$3) title "" linecolor rgb "#00643C" with boxes, \
'' using ($1+0):3 title "" linecolor rgb "#FFC300" with boxes, \
'data/chi25k/chi-part.csv' using ($1+dx):($2+$3) title "" linecolor rgb "#00643C" with boxes, \
'' using ($1+dx):3 title "" linecolor rgb "#FFC300" with boxes

unset ylabel
#unset key
unset label 1
unset label 2
unset label 3

unset arrow 1
unset arrow 2
unset arrow 3

set title "12.5k-V, 50k-E" font ",15"
# Middle plot: 
plot 'data/chi50k/chi-nosgx.csv' using ($1-dx):($2+$3) title "engine" linecolor rgb "#00643C" with boxes, \
'' using ($1-dx):3 title "sharding" linecolor rgb "#FFC300"  with boxes, \
'data/chi50k/chi-full.csv' using ($1+0):($2+$3) title "" linecolor rgb "#00643C" with boxes, \
'' using ($1+0):3 title "" linecolor rgb "#FFC300" with boxes, \
'data/chi50k/chi-part.csv' using ($1+dx):($2+$3) title "" linecolor rgb "#00643C" with boxes, \
'' using ($1+dx):3 title "" linecolor rgb "#FFC300" with boxes

set title "25k-V, 100k-E" font ",15"
set label 4 "Pagerank-Graphchi (V = vertices, E = Edges)" font ",10" at -9,3
# RHS plot: 
plot 'data/chi100k/chi-nosgx.csv' using ($1-dx):($2+$3) title "engine" linecolor rgb "#00643C" with boxes, \
'' using ($1-dx):3 title "sharding" linecolor rgb "#FFC300"  with boxes, \
'data/chi100k/chi-full.csv' using ($1+0):($2+$3) title "" linecolor rgb "#00643C" with boxes, \
'' using ($1+0):3 title "" linecolor rgb "#FFC300" with boxes, \
'data/chi100k/chi-part.csv' using ($1+dx):($2+$3) title "" linecolor rgb "#00643C" with boxes, \
'' using ($1+dx):3 title "" linecolor rgb "#FFC300" with boxes

#---------------------------------------------------------------------------------------------------


!epstopdf "graphchi.eps"
!rm "graphchi.eps"
quit 