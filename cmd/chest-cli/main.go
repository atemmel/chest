package main

import (
	"bufio"
	"fmt"
	"os"

	"chest/pkg/db"

	"golang.org/x/term"
)

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

func createUser() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username?:")
	user, _ := reader.ReadString('\n')
	if user == "" {
		fmt.Println()
		return
	}
	user = user[:len(user) - 1]
	fmt.Print("Password?:")
	pass, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	defaultGroups := []string{
		db.AnyGroup,
		db.UserGroup,
	}

	id, err := db.Register(user, pass, defaultGroups)
	assert(err)
	fmt.Println("OK: new user with id", id, "created")
}

func help() {
	fmt.Println(
`  chest-cli

   useradd - adds a user
`)
}

var (
	mode = ""
)

func init() {
	args := os.Args
	if len(args) > 1 {
		mode = args[1]
	}
}

func main() {
	assert(db.Connect())
	defer func() {
		assert(db.Disconnect())
	}()

	switch mode {
	case "useradd":
		createUser()
	case "-h":
		fallthrough
	case "help":
		fallthrough
	case "-help":
		fallthrough
	case "--help":
		help()
		return
	case "":
		fmt.Println("No command specified, exiting...")
		return
	default:
		fmt.Printf("Unknown command '%s', exiting...\n" , mode)
		return
	}
	//fmt.Println(db.LookupHexId("64fdfa398fac7f1aff66dc30"))
}
