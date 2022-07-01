CryptoKey is an encapsulation for cryptographic keys in Go that makes
cryptographic agility support simple for Go applications.  

CryptoKey uses Coze's `alg` for denoting keys which allows CryptoKey to simplify
the interface for interacting with various keys. See https://github.com/Cyphrme/Coze/blob/base64/alg.go#L13 for more on `alg`.  



# Dev
## Go Mod
To import Coze, Go needs the lower case string for `go get`

```
go get github.com/cyphrme/coze@base64
```

## See also
[Coze](https://github.com/Cyphrme/Coze/blob/base64/alg.go#L13)