#!/bin/bash

DATA="./fbedges"

#remove previous generated data file
rm "./data"

#to estimate the final file size do:
#334 x n ~ n MB

for i in $(seq 1 355); do
    cat $DATA >>"data"
done
