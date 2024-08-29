#!/bin/bash
cd ubuntu
docker build -t mtd/ubuntu .
cd ..
cd dionaea
docker build -t mtd/dionaea .
cd ..
cd heralding
docker build -t heralding .
cd ..
cd snort
docker build -t mtd/snort .
cd ..
cd ryu
docker build -t mtd/ryu .
cd ..
cd frr
docker build -t mtd/frr .
cd ..



