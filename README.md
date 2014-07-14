# Red Authentication Service
A proof-of-concept that separates authentication out into a microservice.

## Installing
`go get github.com/lestopher/redauthservice`

## Running
`redauth -local=":8000" -conf="/path/to/secure_config.yml"`

## Usage
`curl -XPOST -d "username=chris&password=password" http://localhost:8000/authenticate`

## Responses
### Success
http status: 200
```
{
  Success: true
}
```
### Failure
http status: 406
```
{
  Success: false,
  Messsage: "crypto/bcrypt: hashedPassword is not the hash of the given password"
}
```
