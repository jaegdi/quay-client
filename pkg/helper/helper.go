package helper

import (
	"fmt"

	"github.com/jaegdi/quay-client/pkg/cli"
)

func Verify(s ...interface{}) {
	flags := cli.GetFlags()
	if flags.Verify {
		fmt.Println(s...)
	}
}

func Verifyf(f string, values ...interface{}) {
	flags := cli.GetFlags()
	if flags.Verify {
		fmt.Printf(f, values...)
	}
}
