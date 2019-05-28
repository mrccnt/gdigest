# gdigest

[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![goreportcard](https://goreportcard.com/badge/github.com/mrccnt/gdigest)](https://goreportcard.com/report/github.com/mrccnt/gdigest)

gdigest handles HTTP Digest (Access) Authentication. Basically a straight-forward implementation after existing wiki page.
Nothing fancy...

gdigest supports:

 * Algorithm: Undefined, MD5 and MD5-session
 * Quality of protection: Undefined, auth and auth-int
 * Unique client nonce per request
 * Nonce counter

## Example

```go
package main

import (
    "fmt"
    "github.com/mrccnt/gdigest"
    "io/ioutil"
    "net/http"
    "strings"
    "time"
)

func main()  {
    
    // Create a new digest reference for given host, user and pass.
    // In this example we are dealing with a CalDAV server.
    digest := gdigest.NewDigest("<username>", "<password>", "https://cal.example.com")
    
    // Every time you need to send an authenticated request to the server
    // you need to fetch a seperate authorization header. In this case we want to
    // fetch calendar data from a server via REPORT method at given URI.
    authString, err := digest.Do("/calendars/<username>/default", "REPORT", "")
    if err != nil {
        panic(err)
    }
    
    fmt.Println(authString)
}
```

As a result of calling `digest.Do()` the ready to use http authorization header will be returned as a string. This
header can be used for the next digest (access) authenticated http request.

Beautified authorization header example:

    Digest  realm="ExampleCalendar",
            nonce="a39bbdf0983957e6",
            algorithm="MD5",
            qop="auth",
            nc="00000001",
            cnonce="55e0a867f0fc959b",
            response="5a7ab8e5b9ffb7005a7ab8e5b9ffb70a",
            opaque="50849db2c592506cf600cc2e68485efa",
            uri="/calendars/acme/default",
            username="acme"

## Links

 * [Digest Access Authentication](https://en.wikipedia.org/wiki/Digest_access_authentication)
