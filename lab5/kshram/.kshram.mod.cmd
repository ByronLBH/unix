cmd_/home/ByronLin/lab5/kshram/kshram.mod := printf '%s\n'   kshram.o | awk '!x[$$0]++ { print("/home/ByronLin/lab5/kshram/"$$0) }' > /home/ByronLin/lab5/kshram/kshram.mod
