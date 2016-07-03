gcc -Wall -Wno-unused-function -O2 --std=c99 -I src/ -I ./ bench_privkey.c timer.c -lgmp -o bench_privkey || { echo "Benchmark compile exited with $?"; exit 1; }
time nice -n -10 ./bench_privkey "${1:-18}"
