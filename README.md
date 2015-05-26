Okita (**O**pen **K**ernel **I**nstrumenting **T**o **A**ssembly) is currently a set of proof-of-concepts aiming at disassembling binaries to asm sources.

The main goal is to be able to do :

```
./naive_disassembler.py binary_to_disass
nasm -f bin generated_source.asm -o generated_bin
```

So binary_to_disass == generated_bin first and foremost.

An example with `samples/helloworld`:

```
$ ./naive_disassembler3.py sample/helloworld
$ nasm -f bin sample/helloworld_naive_disass.asm -o sample/helloworld_naive_disass
$ md5sum sample/helloworld sample/helloworld_naive_disass
a28c100b7fe480b5e19d00bb73ca027b  samples/helloworld_naive_disass
a28c100b7fe480b5e19d00bb73ca027b  samples/helloworld
```

Obviously the goal is to generate asm listing as clear as possible, with labels and symbols.

Once the asm file(s) would get documented enough, one would get a better control over an unknown, black-boxed binary.

The ultime goal would be to modify the binary with ease, without relying on memory patching or writing bytes with an hex editor.

This is a very challenging task since you have to write asm code to fit into the binary. There is neither compilation nor linking summoned at this stage,
it's all binary instrumentation.

Okita relies on the powerful capstone disassembly framework to saber binaries. :D

At the moment, the proofs of concept are written in python since this is easier to code with.
Later on, Okita is expected to be written in full C++ with classes language since it provides way more execution speed.


Last but not least, I've chosen Okita since he was a powerful warrior and the captain of the first *ban tai* of the Shinsengumi. :D
