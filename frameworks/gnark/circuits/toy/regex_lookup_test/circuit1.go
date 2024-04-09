package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const (
	stringLength    = 7
	flattenedStates = 5
	statesLength    = 5
	totalChar       = 6
)

type Circuit struct {
	// Tagging a variable is optional. Default uses variable name and secret visibility.
	PrivateString [stringLength]frontend.Variable `gnark:",secret"`
	Queries       [totalChar]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	transitions := []struct {
		chars    []rune
		currNode int
		nextNode int
		typ      int
	}{
		{[]rune{'e', 'r'}, 0, 1, 0},
		{[]rune{'e'}, 1, 2, 0},
		{[]rune{'n'}, 2, 3, 0},
		{[]rune{'.'}, 3, 4, 0},
		{[]rune{'t'}, 4, 5, 0},
	}
	transitionTable := logderivlookup.New(api)
	results := [stringLength]frontend.Variable{}

	for i := range results {
		results[i] = api.Add(0, 0)
	}

	for _, transition := range transitions {
		// Then loop through each char in the transition
		for _, char := range transition.chars {
			// Convert the rune to int64 and add as key
			key := api.Add(0, int64(char))
			api.Println("added key to table", key)
			// Adding key to the lookup table
			transitionTable.Insert(key)
		}
	}

	if stringLength < statesLength {
		return fmt.Errorf("Text too short to satisfy.")
	}

	for i := 0; i <= stringLength-statesLength; i++ {
		lookupIndex := 0
		keys := [5]frontend.Variable{c.PrivateString[i+0], c.PrivateString[i+1], c.PrivateString[i+2], c.PrivateString[i+3], c.PrivateString[i+4]}
		tempVar0 := api.Or(api.IsZero(api.Sub(transitionTable.Lookup(c.Queries[lookupIndex])[0], keys[0])), api.IsZero(api.Sub(transitionTable.Lookup(c.Queries[lookupIndex+1])[0], keys[0])))
		api.Println("tempVar0 comparison", tempVar0)
		tempVar1 := api.IsZero(api.Sub(transitionTable.Lookup(c.Queries[lookupIndex+2])[0], keys[1]))
		api.Println("tempVar1 comparison", tempVar1)
		tempVar2 := api.IsZero(api.Sub(transitionTable.Lookup(c.Queries[lookupIndex+3])[0], keys[2]))
		api.Println("tempVar2 comparison", tempVar2)
		tempVar3 := api.IsZero(api.Sub(keys[3], keys[3]))
		api.Println("tempVar3 comparison", tempVar3)
		tempVar4 := api.IsZero(api.Sub(transitionTable.Lookup(c.Queries[lookupIndex+5])[0], keys[4]))
		api.Println("tempVar4 comparison", tempVar4)

		results[i] = api.And(api.And(api.And(api.And(tempVar0, tempVar1), tempVar2), tempVar3), tempVar4)

	}
	finalResult := frontend.Variable(0)
	for _, result := range results {
		finalResult = api.Or(finalResult, result)
		api.Println("finalResult inside loop", finalResult)
	}
	api.Println("finalResult after loop", finalResult)
	api.AssertIsEqual(finalResult, 1)

	return nil
}

func main() {
	witnessCircuit := Circuit{}
	// fill queries
	for i := range witnessCircuit.Queries {
		witnessCircuit.Queries[i] = i
	}
	privateString := make([]*big.Int, stringLength)
	inputString := "virenet"
	for i, char := range inputString {
		if i < stringLength {
			privateString[i] = big.NewInt(int64(char))
			witnessCircuit.PrivateString[i] = privateString[i]
		}
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	secretWitness, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	publicWitness, err := secretWitness.Public()
	if err != nil {
		log.Fatal(err)
	}

	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		log.Fatal(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Println("done")
}
