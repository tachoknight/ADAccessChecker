package main

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "path/filepath"

    ldap "gopkg.in/ldap.v2"
    yaml "gopkg.in/yaml.v1"
)

// Sample search using wget where id is the uidNumber attribute
// 	wget -O- --post-data='{"id": 5039,"groupname":"EpilogAuthorized,OU=Epilog,OU=CNC,OU=Authorized Groups,OU=Domain Groups"}' --header=Content-Type:application/json "http://localhost:5000/checkauth"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// O U R  S T R U C T U R E S
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type ldapConfig struct {
    Server     string `yaml:server`
    Port       int64  `yaml:port`
    SearchUser string `yaml:searchuser`
    SearchPass string `yaml:searchpass`
    BaseDN     string `yaml:basedn`
    SearchAttr string `yaml:searchattr`
}

type authRequest struct {
    ID        int    `json:"id"`
    GroupName string `json:"groupname"`
}

type authResponse struct {
    ResponseOK bool              `json:"txok"`
    Message    string            `json:"message"`
    Data       map[string]string `json:"data"`
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// O U R  V A R I A B L E S
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
var config ldapConfig

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// T R A N S F O R M A T I O N
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func streamToString(data []byte) string {
    return string(data[:])
}

func transformJSONToObject(jsonData []byte, v interface{}) {
    decoder := json.NewDecoder(bytes.NewReader([]byte(jsonData)))

    err := decoder.Decode(&v)
    if err != nil {
        panic(err)
    }
}

func transformObjectToJSON(v interface{}) []byte {
    jsonBytes, err := json.Marshal(v)
    if err != nil {
        log.Println(err)
        return nil
    }

    return jsonBytes
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// W O R K
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func checkAccessForUser(ar authRequest) authResponse {
    var r authResponse

    l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.Server, config.Port))
    if err != nil {
        log.Fatal(err)
        r.ResponseOK = false
        r.Message = err.Error()
        return r
    }
    defer l.Close()

    // Reconnect with TLS
    err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
    if err != nil {
        log.Fatal(err)
        r.ResponseOK = false
        r.Message = err.Error()
        return r
    }

    err = l.Bind(config.SearchUser, config.SearchPass)
    if err != nil {
        log.Fatal(err)
        r.ResponseOK = false
        r.Message = err.Error()
        return r
    }

    //
    // Now we can begin searching...we need to do two searches:
    // The first is to find the user based on the ID, and then,
    // assuming we do find him or her, are they in the group
    // we're looking for?
    //

    //
    // First search, find the user
    //
	
    userSearchRequest := ldap.NewSearchRequest(
        config.BaseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        fmt.Sprintf("(&(objectClass=user)(%s=%d))", config.SearchAttr, ar.ID),
        []string{"sAMAccountName"}, // just want the name
        nil,
    )

    usr, err := l.Search(userSearchRequest)
    if err != nil {
        log.Fatal(err)
        r.ResponseOK = false
        r.Message = err.Error()
        return r
    }

    foundUser := false
    sAMAccountName := ""
    for _, entry := range usr.Entries {
        sAMAccountName = entry.GetAttributeValue("sAMAccountName")
        fmt.Printf("Found %s -> %v\n", entry.DN, entry.GetAttributeValue("sAMAccountName"))
        foundUser = true
    }

    if foundUser == false {
        r.ResponseOK = false
        r.Message = fmt.Sprintf("%d was not found in the directory", ar.ID)
        return r
    }

    //
    // Second search, is the user in the group we're looking for?
    //

    // Example group is:
    //         EpilogAuthorized,OU=Epilog,OU=CNC,OU=Authorized Groups,OU=Domain Groups
    groupSearchRequest := ldap.NewSearchRequest(
        config.BaseDN,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s)(memberOf=CN=%s,%s))", sAMAccountName, ar.GroupName, config.BaseDN),
        []string{"sAMAccountName"}, // just want the name
        nil,
    )

    gsr, err := l.Search(groupSearchRequest)
    if err != nil {
        log.Fatal(err)
        r.ResponseOK = false
        r.Message = err.Error()
        return r
    }

    userInGroup := false
    for _, entry := range gsr.Entries {
        sAMAccountName = entry.GetAttributeValue("sAMAccountName")
        fmt.Printf("Found in the group! %s -> %v\n", entry.DN, entry.GetAttributeValue("sAMAccountName"))
        userInGroup = true
    }

    if userInGroup == false {
        r.ResponseOK = false
        r.Message = fmt.Sprintf("User %s with ID %d not in the %s group", sAMAccountName, ar.ID, ar.GroupName)
        return r
    }

    // If we're here, yes, the user can use the equipment
    r.ResponseOK = true
    r.Message = "OK"
    return r
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// H A N D L E R
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func checkAuth(w http.ResponseWriter, r *http.Request) {
    log.Println("====> getAuthorization")
    defer log.Println("<====  getAuthorization")

    bodyPayload, err := ioutil.ReadAll(r.Body)
    if err != nil {
        panic(err)
    }
    // First thing we need is a login struct from the http request
    var ar authRequest
    transformJSONToObject(bodyPayload, &ar)
    log.Printf("Got %d, %s\n", ar.ID, ar.GroupName)

    fmt.Fprintf(w, "%s", transformObjectToJSON(checkAccessForUser(ar)))
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// S T A R T
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func setup() bool {
    log.Println("\tReading config...")

    filename, _ := filepath.Abs("./settings.yaml")
    yamlFile, err := ioutil.ReadFile(filename)
    if err != nil {
        log.Printf("Could not open YAML file: %s\n", err.Error())
        return false
    }

    err = yaml.Unmarshal(yamlFile, &config)
    if err != nil {
        log.Printf("Could not parse YAML file: %s\n", err.Error())
        return false
    }

    return true
}

func main() {
    log.Println("**** Starting server ****")

    configOk := setup()
    if configOk == false {
        log.Println("Did not setup correctly, so not continuing...")
        return
    }

    http.HandleFunc("/checkauth", checkAuth)

    // And allow us to serve up our index page
    http.Handle("/", http.FileServer(http.Dir("./")))

    //
    // And here we go, listening on port 5000
    //
    log.Println("\tServer is up and we're listening...")
    http.ListenAndServe(":5000", nil)

    log.Println("**** Server shutdown ****")
}

