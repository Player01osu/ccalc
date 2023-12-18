
# ccalc

Calculator

## Features

#### Working

- Simple arithmetic
- Defining variables

#### On The Way

- Derivatives
- Defining functions
- Built-in functions and constants
- Numerical integration

#### Maybe

- Full integration

## Quickstart

```console
./x
```

```console
./target/ccalc
```

```
*> 1 + 1
2.0
*> sin(pi / 2)
1.0
*> f(x) = x^2
f(x) = x^2
*> f'(x)
2x
```

## About the code

This project uses [arena allocation](https://github.com/ccgargantua/arena-allocator)
as its primary memory management model. All calls to malloc must be freed in the
same scope, and things should be created on the stack whenever possible.
