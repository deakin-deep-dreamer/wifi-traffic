package main

import "fmt"

func makeOddGenerator() func() uint8 {
	i := uint8(1)
	return func() uint8 {
		i += 2
		return i
	}
}

func main() {
	// nextOdd := makeOddGenerator()
	// fmt.Println(nextOdd())
	// fmt.Println(nextOdd())
	// fmt.Println(nextOdd())

	fmt.Println("Start...")
	for {
		mainLoop()
	}
}
