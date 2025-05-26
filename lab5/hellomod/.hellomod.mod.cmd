cmd_/home/ByronLin/lab5/hellomod/hellomod.mod := printf '%s\n'   hellomod.o | awk '!x[$$0]++ { print("/home/ByronLin/lab5/hellomod/"$$0) }' > /home/ByronLin/lab5/hellomod/hellomod.mod
