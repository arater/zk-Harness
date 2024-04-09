package nfa_regex

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark/frontend"
)

const (
	stringLength    = 9
	substringLength = 985
)

type NfaRegexCircuit struct {
	// Tagging a variable is optional. Default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",secret"`
	A [stringLength]frontend.Variable
	B [substringLength]frontend.Variable `gnark:",public"`
}

func multipleAnd(api frontend.API, vars []frontend.Variable) frontend.Variable {
	if len(vars) == 0 {
		log.Fatal("multipleAnd called with an empty slice")
	}
	result := vars[0]
	for _, v := range vars[1:] {
		result = api.And(result, v)
	}
	return result
}

func multipleOr(api frontend.API, vars []frontend.Variable) frontend.Variable {
	if len(vars) == 0 {
		log.Fatal("multipleOr called with an empty slice")
	}
	result := vars[0]
	for _, v := range vars[1:] {
		result = api.Or(result, v)
	}
	return result
}

var signal [6]frontend.Variable

func (circuit *NfaRegexCircuit) Define(api frontend.API) error {
	rest := frontend.Variable(0)

	for i := 0; i < len(circuit.B)-5; i++ {

		rest = multipleOr(api, []frontend.Variable{multipleAnd(api, []frontend.Variable{
			multipleOr(api, []frontend.Variable{api.IsZero(api.Sub(frontend.Variable(101), circuit.B[i+0])), api.IsZero(api.Sub(frontend.Variable(101), circuit.B[i+0])), api.IsZero(api.Sub(frontend.Variable(114), circuit.B[i+0])), api.IsZero(api.Sub(frontend.Variable(114), circuit.B[i+0]))}), multipleAnd(api, []frontend.Variable{api.IsZero(api.Sub(frontend.Variable(101), circuit.B[i+1])), api.IsZero(api.Sub(frontend.Variable(110), circuit.B[i+2]))}), multipleAnd(api, []frontend.Variable{api.IsZero(0)}), multipleAnd(api, []frontend.Variable{api.IsZero(api.Sub(frontend.Variable(116), circuit.B[i+4]))})}), rest})
	}

	api.AssertIsEqual(rest, 1)

	return nil
}

// Logic to use the signal array in your circuit

func main() {

	var circuit NfaRegexCircuit

	a := make([]*big.Int, stringLength)
	inputString := "(e|r)en.t"
	for i, char := range inputString {
		if i < stringLength {
			a[i] = big.NewInt(int64(char))
		}
	}

	b := make([]*big.Int, substringLength)
	regexPattern := "In a small town nestled between rolling hills and vast fields, there lived a wise old man known throughout the lands for his profound wisdom and keen insight. People from villages far and wide would journey to seek his counsel on matters both big and small. His home, a quaint cottage adorned with flowering vines and surrounded by an enchanting garden, was a place of serenity and reflection. As the seasons changed, so did the questions of those who visited him. Yet, no matter the query, the wise man always had the right words to offer. It wasnt until a rainy evening, when a curious traveler inquired about the essence of happiness, that the wise man shared a secret long held close: true contentment is found not in seeking more, but in appreciating the present moment. The traveler pondered this as they noticed a sereneti painting on the wall, its colors vibrant even as dusk fell. The wise mans lesson was clear and resonant, echoing the travelers own beliefs and experiences."
	for i, char := range regexPattern {
		if i < substringLength {
			b[i] = big.NewInt(int64(char))
		}
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	_r1cs := ccs.(*cs.SparseR1CS) // here is optional can be used with r1cs as well
	srs, err := test.NewKZGSRS(_r1cs)
	if err != nil {
		panic(err)
	}

	{

		var w NfaRegexCircuit
		w.X = 2
		w.Y = 4

		for i := 0; i < stringLength; i++ {
			w.A[i] = a[i]
		}

		for i := 0; i < substringLength; i++ {
			w.B[i] = b[i]
		}

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		pk, vk, err := plonk.Setup(ccs, srs)
		if err != nil {
			log.Fatal(err)
		}

		proof, err := plonk.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		err = plonk.Verify(proof, vk, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}
	}

	{
		var w, pW NfaRegexCircuit
		w.X = 2

		w.Y = 4096

		for i := 0; i < stringLength; i++ {
			w.A[i] = a[i]
		}
		for i := 0; i < substringLength; i++ {
			w.B[i] = b[i]
		}

		pW.X = 3
		pW.Y = 4096

		for i := 0; i < stringLength; i++ {
			pW.A[i] = a[i]
		}
		for i := 0; i < substringLength; i++ {
			pW.B[i] = b[i]
		}

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&pW, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		pk, vk, err := plonk.Setup(ccs, srs)

		if err != nil {
			log.Fatal(err)
		}

		proof, err := plonk.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		err = plonk.Verify(proof, vk, witnessPublic)
		if err == nil {
			log.Fatal("Error: wrong proof is accepted")
		}
	}

}
