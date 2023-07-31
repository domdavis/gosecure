# Go Secure

![Build](https://img.shields.io/github/actions/workflow/status/domdavis/gosecure/build.yml)
![Issues](https://img.shields.io/github/issues/domdavis/gosecure?style=plastic)
![Pull Requests](https://img.shields.io/github/issues-pr/domdavis/gosecure?style=plastic)
[![Go Doc](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=plastic)](http://godoc.org/bitbucket.org.idomdavis/gosecure)
[![License](https://img.shields.io/badge/license-MIT-green?style=plastic)](https://opensource.org/licenses/MIT)

`gosecure` provides a generic way to hash passphrases. It supports bcrypt and 
argon2id, with the ability to use multiple algorithms when comparing a hash so
that migration from one algorithm to another can be handled. 

Hash comparison is done in constant time with sensible defaults used for this
time, the hashing algorithm, and the minimum passphrase length should none be
set.

`gosecure` also provides some wrapped functions from `crypto/rand` which will
panic rather than returning an error.

## Installation

```shell script
go get -u bitbucket.org/idomdavis/gosecure
```
