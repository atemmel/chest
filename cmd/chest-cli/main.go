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

func addUser() {
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

func deleteUser() {
	if arg1 == "" {
		fmt.Println("Error: user to delete not specified")
		return
	}

	count, err := db.Delete(arg1)
	assert(err)
	fmt.Println("OK: deleted", count, " users with name", arg1)
}

func listUser() {
	users, err := db.List()
	assert(err)

	for _, u := range users {
		fmt.Println(u.Username)
	}
}

func help() {
	fmt.Println(
`  chest-cli

   useradd - adds a user
   userdel <name> - deletes user with name <name>
`)
}

var (
	mode = ""
	arg1 = ""
)

func init() {
	args := os.Args
	if len(args) > 1 {
		mode = args[1]
	}
	if len(args) > 2 {
		arg1 = args[2]
	}
}

func main() {
	assert(db.Connect())
	defer func() {
		assert(db.Disconnect())
	}()

	switch mode {
	case "useradd":
		addUser()
	case "userdel":
		deleteUser()
	case "userlist":
		listUser()
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
