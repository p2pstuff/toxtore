Toxtore
=======

A library for Tox message history storage and multi-device synchronization.

How to build
------------

Dependencies:

- `cmake`
- `toxcore`
- `sqlcipher`: encrypted sqlite

```
mkdir build; cd build
cmake ..
make
```

Try it out directly
-------------------

Toxtore includes a small client based on [minitox](https://github.com/hqwrong/minitox) called
`mdmt`, a shorthand for multi-device minitox. To run it, type `./mdmt` when in the `build`
directory. `mdmt` is not installed to the system when running `make install`.


Porting a Tox client to Toxtore
-------------------------------

The `doc/toxtore_design.md` and `include/toxtore.h` files contain some informations on the Toxtore
internals that might be helpful. The source code of mdmt at `src/minitox.c` can also be used
as an example of Toxtore usage.
