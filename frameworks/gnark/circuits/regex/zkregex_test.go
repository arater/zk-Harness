package regex

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var regexCircuit RegexCircuit

	// assert.ProverFailed(&regexCircuit, &RegexCircuit{
	// 	Hash:     42,
	// 	PreImage: 42,
	// })

	for i := range regexCircuit.Queries {
		regexCircuit.Queries[i] = i
	}
	privateString := make([]*big.Int, stringLength)
	inputString := "virenet"
	for i, char := range inputString {
		if i < stringLength {
			privateString[i] = big.NewInt(int64(char))
			regexCircuit.PrivateString[i] = privateString[i]
		}
	}

	assert.SolvingSucceeded(&RegexCircuit{}, &regexCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

	assert.ProverSucceeded(&RegexCircuit{}, &regexCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}
