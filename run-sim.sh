#!/bin/bash
#
# Copyright (c) 2020 Peterson Yuhala, IIUN
#

#change directory to present dir
cd "$(dirname "$0")"

# vary the % of secure classes
# and rebuild native image

sim_script="$PWD/sim.sh"
bench_script="$PWD/sgx/run-bench.sh"
email="petersonyuhala@gmail.com"

function send_email () {
    mailx -s "Benchmark completed" "$email"
}

vals=(1 10 20 30 40 50 60 70 80 90 94 95 96 97 98 99)
#vals=(94 95 96)
for i in ${vals[@]}; do
    #build simulation app
    /bin/bash $sim_script $i 
    #run the sgx bench script
    /bin/bash $bench_script $i
done




