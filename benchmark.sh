time gcc -Wall -Wno-unused-function -O2 --std=c99 -I src/ -I ./ bench_privkey.c timer.c -lgmp -o bench_privkey || exit
time ./bench_privkey 18
